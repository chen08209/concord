use std::collections::VecDeque;
use std::io::{IoSlice, IoSliceMut};
use std::sync::Mutex;

use concord_common::sync::lock;

use crate::seq::Seq;

pub(crate) const CHUNK: usize = 16 * 1024;
const POOL_LIMIT: usize = 512;

/// Fixed-size chunks recycled between connections, so a busy stack does not allocate per
/// segment and an idle one returns its memory.
#[derive(Default)]
pub struct ChunkPool {
    free: Mutex<Vec<Box<[u8]>>>,
}

impl ChunkPool {
    fn take(&self) -> Box<[u8]> {
        lock(&self.free)
            .pop()
            .unwrap_or_else(|| vec![0u8; CHUNK].into_boxed_slice())
    }

    fn give(&self, chunk: Box<[u8]>) {
        let mut free = lock(&self.free);
        if free.len() < POOL_LIMIT {
            free.push(chunk);
        }
    }

    pub fn cached(&self) -> usize {
        lock(&self.free).len()
    }

    pub fn trim(&self) {
        lock(&self.free).clear();
    }
}

/// A byte queue in pool chunks: appended at the back, read at any offset, consumed from
/// the front.
#[derive(Default)]
pub(crate) struct ByteQueue {
    chunks: VecDeque<Box<[u8]>>,
    head: usize,
    len: usize,
}

impl ByteQueue {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn push(&mut self, pool: &ChunkPool, mut data: &[u8]) {
        while !data.is_empty() {
            let tail = self.head + self.len;
            let (index, within) = (tail / CHUNK, tail % CHUNK);
            if index >= self.chunks.len() {
                self.chunks.push_back(pool.take());
            }
            let take = (CHUNK - within).min(data.len());
            let (now, rest) = data.split_at(take);
            let Some(dst) = self
                .chunks
                .get_mut(index)
                .and_then(|chunk| chunk.get_mut(within..within + take))
            else {
                return;
            };
            dst.copy_from_slice(now);
            self.len += take;
            data = rest;
        }
    }

    /// Copies `out.len()` bytes starting `offset` bytes into the queue. False when the queue
    /// is too short.
    pub fn copy_at(&self, offset: usize, out: &mut [u8]) -> bool {
        if offset + out.len() > self.len {
            return false;
        }
        let mut pos = self.head + offset;
        let mut written = 0;
        while written < out.len() {
            let (index, within) = (pos / CHUNK, pos % CHUNK);
            let Some(chunk) = self.chunks.get(index) else {
                return false;
            };
            let take = (CHUNK - within).min(out.len() - written);
            match (
                out.get_mut(written..written + take),
                chunk.get(within..within + take),
            ) {
                (Some(dst), Some(src)) => dst.copy_from_slice(src),
                _ => return false,
            }
            written += take;
            pos += take;
        }
        true
    }

    /// None when the range spans more chunks than `out` holds.
    pub fn slices_at<'a>(
        &'a self,
        offset: usize,
        len: usize,
        out: &mut [IoSlice<'a>],
    ) -> Option<usize> {
        if offset + len > self.len {
            return None;
        }
        let mut pos = self.head + offset;
        let end = pos + len;
        let mut count = 0;
        while pos < end {
            let (index, within) = (pos / CHUNK, pos % CHUNK);
            let take = (CHUNK - within).min(end - pos);
            let bytes = self.chunks.get(index)?.get(within..within + take)?;
            *out.get_mut(count)? = IoSlice::new(bytes);
            count += 1;
            pos += take;
        }
        Some(count)
    }

    pub fn consume(&mut self, pool: &ChunkPool, n: usize) {
        let n = n.min(self.len);
        self.head += n;
        self.len -= n;
        if self.len == 0 {
            self.head = 0;
            while let Some(chunk) = self.chunks.pop_front() {
                pool.give(chunk);
            }
            return;
        }
        while self.head >= CHUNK {
            let Some(chunk) = self.chunks.pop_front() else {
                break;
            };
            pool.give(chunk);
            self.head -= CHUNK;
        }
    }

    pub fn front_slices<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        let end = self.head + self.len;
        let mut pos = self.head;
        let mut count = 0;
        for slot in out.iter_mut() {
            let (index, within) = (pos / CHUNK, pos % CHUNK);
            let take = (CHUNK - within).min(end - pos);
            let Some(bytes) = self
                .chunks
                .get(index)
                .and_then(|chunk| chunk.get(within..within + take))
                .filter(|bytes| !bytes.is_empty())
            else {
                break;
            };
            *slot = IoSlice::new(bytes);
            count += 1;
            pos += take;
        }
        count
    }

    /// Room for up to `max` more bytes after the queued ones; `commit` keeps what was
    /// written there and `trim` returns the rest to the pool.
    pub fn spare_slices<'a>(
        &'a mut self,
        pool: &ChunkPool,
        max: usize,
        out: &mut [IoSliceMut<'a>],
    ) -> usize {
        let tail = self.head + self.len;
        let mut end = tail;
        for _ in 0..out.len() {
            end = ((end / CHUNK + 1) * CHUNK).min(tail + max);
        }
        while self.chunks.len() < end.div_ceil(CHUNK) {
            self.chunks.push_back(pool.take());
        }
        let mut pos = tail;
        let mut count = 0;
        for (slot, chunk) in out.iter_mut().zip(self.chunks.range_mut(tail / CHUNK..)) {
            let within = pos % CHUNK;
            let take = (CHUNK - within).min(end - pos);
            let Some(bytes) = chunk
                .get_mut(within..within + take)
                .filter(|bytes| !bytes.is_empty())
            else {
                break;
            };
            *slot = IoSliceMut::new(bytes);
            count += 1;
            pos += take;
        }
        count
    }

    pub fn commit(&mut self, pool: &ChunkPool, n: usize) {
        self.len += n;
        self.trim(pool);
    }

    pub fn trim(&mut self, pool: &ChunkPool) {
        while self.chunks.len() > (self.head + self.len).div_ceil(CHUNK) {
            let Some(chunk) = self.chunks.pop_back() else {
                break;
            };
            pool.give(chunk);
        }
    }

    /// Copies up to `out.len()` bytes from the front and consumes them.
    pub fn read(&mut self, pool: &ChunkPool, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len);
        if let Some(dst) = out.get_mut(..n) {
            self.copy_at(0, dst);
        }
        self.consume(pool, n);
        n
    }
}

/// Segments received ahead of `rcv_nxt`, kept sorted and disjoint.
#[derive(Default)]
pub(crate) struct Reassembly {
    ranges: Vec<(Seq, Vec<u8>)>,
    bytes: usize,
    /// Start of the range that took the latest segment, reported first in SACK.
    latest: Option<Seq>,
}

pub(crate) const MAX_RANGES: usize = 64;

impl Reassembly {
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Stores `data` at `seq`, which is after `rcv_nxt`. Bytes already held are dropped.
    /// Returns false when nothing new was stored.
    pub fn insert(&mut self, seq: Seq, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let end = seq + data.len() as u32;
        let first = self
            .ranges
            .partition_point(|(s, d)| (*s + d.len() as u32).lt(seq));
        let mut last = first;
        while let Some((s, _)) = self.ranges.get(last)
            && s.le(end)
        {
            last += 1;
        }
        let overlapping = self.ranges.get(first..last).unwrap_or_default();
        if let [(s, d)] = overlapping
            && s.le(seq)
            && end.le(*s + d.len() as u32)
        {
            self.latest = Some(*s);
            return false;
        }
        if overlapping.is_empty() && self.ranges.len() >= MAX_RANGES {
            return false;
        }
        let old: usize = overlapping.iter().map(|(_, d)| d.len()).sum();
        let mut absorbed = self.ranges.drain(first..last);
        let (start, mut merged) = match absorbed.next() {
            Some((s, d)) if s.le(seq) => (s, d),
            Some((s, d)) => {
                let mut prefix = Vec::with_capacity(d.len() + s.since(seq) as usize);
                prefix.extend_from_slice(data.get(..s.since(seq) as usize).unwrap_or_default());
                prefix.extend_from_slice(&d);
                (seq, prefix)
            }
            None => (seq, Vec::new()),
        };
        for (s, d) in absorbed {
            let held = start + merged.len() as u32;
            merged.extend_from_slice(
                data.get(held.since(seq) as usize..s.since(seq) as usize)
                    .unwrap_or_default(),
            );
            merged.extend_from_slice(&d);
        }
        let held = start + merged.len() as u32;
        if held.lt(end) {
            merged.extend_from_slice(data.get(held.since(seq) as usize..).unwrap_or_default());
        }
        self.bytes = self.bytes - old + merged.len();
        self.ranges.insert(first, (start, merged));
        self.latest = Some(start);
        true
    }

    /// Removes and returns the data that now continues from `rcv_nxt`, if any.
    pub fn take_ready(&mut self, rcv_nxt: Seq) -> Option<Vec<u8>> {
        while let Some((start, len)) = self.ranges.first().map(|(s, d)| (*s, d.len())) {
            if (start + len as u32).le(rcv_nxt) {
                self.bytes -= len;
                self.ranges.remove(0);
                continue;
            }
            if start.gt(rcv_nxt) {
                return None;
            }
            let (_, mut data) = self.ranges.remove(0);
            self.bytes -= len;
            if self.latest == Some(start) {
                self.latest = None;
            }
            data.drain(..rcv_nxt.since(start) as usize);
            return Some(data);
        }
        None
    }

    /// SACK blocks, the most recently changed range first.
    pub fn sack_blocks(&self, out: &mut Vec<(Seq, Seq)>, limit: usize) {
        out.clear();
        let latest = self
            .latest
            .and_then(|l| self.ranges.iter().find(|(s, _)| *s == l));
        if let Some((s, d)) = latest {
            out.push((*s, *s + d.len() as u32));
        }
        for (s, d) in self.ranges.iter().rev() {
            if out.len() >= limit {
                break;
            }
            if Some(*s) != self.latest {
                out.push((*s, *s + d.len() as u32));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_reads_across_chunks_and_returns_them() {
        let pool = ChunkPool::default();
        let mut queue = ByteQueue::default();
        let data: Vec<u8> = (0..(CHUNK * 3 + 77)).map(|i| i as u8).collect();
        queue.push(&pool, &data[..1000]);
        queue.push(&pool, &data[1000..]);
        assert_eq!(queue.len(), data.len());
        let mut mid = vec![0u8; CHUNK + 10];
        assert!(queue.copy_at(CHUNK - 5, &mut mid));
        assert_eq!(mid, data[CHUNK - 5..2 * CHUNK + 5]);
        let mut slices = [IoSlice::new(&[]); 3];
        let count = queue.slices_at(CHUNK - 5, CHUNK + 10, &mut slices).unwrap();
        let joined: Vec<u8> = slices[..count]
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect();
        assert_eq!(joined, mid);
        assert!(queue.slices_at(0, 3 * CHUNK + 1, &mut slices).is_none());
        assert!(queue.slices_at(CHUNK, data.len(), &mut slices).is_none());
        queue.consume(&pool, CHUNK + 3);
        let mut rest = vec![0u8; data.len()];
        let n = queue.read(&pool, &mut rest);
        assert_eq!(&rest[..n], &data[CHUNK + 3..]);
        assert!(queue.is_empty());
        assert_eq!(pool.cached(), 4);
        queue.push(&pool, b"again");
        let mut out = [0u8; 5];
        assert_eq!(queue.read(&pool, &mut out), 5);
        assert_eq!(&out, b"again");
    }

    #[test]
    fn slices_cover_the_queue_and_spare_room_extends_it() {
        let pool = ChunkPool::default();
        let mut queue = ByteQueue::default();
        let data: Vec<u8> = (0..(CHUNK * 2 + 100)).map(|i| (i % 251) as u8).collect();
        queue.push(&pool, &data[..CHUNK - 10]);
        queue.consume(&pool, 30);
        let mut spare: [IoSliceMut<'_>; 4] = std::array::from_fn(|_| IoSliceMut::new(&mut []));
        let count = queue.spare_slices(&pool, CHUNK + 120, &mut spare);
        assert_eq!(count, 3);
        let room: usize = spare[..count].iter().map(|s| s.len()).sum();
        assert_eq!(room, CHUNK + 120);
        let mut copied = 0;
        let fill = &data[CHUNK - 10..];
        for slice in spare[..count].iter_mut() {
            let take = slice.len().min(fill.len() - copied);
            slice[..take].copy_from_slice(&fill[copied..copied + take]);
            copied += take;
        }
        queue.commit(&pool, copied);
        assert_eq!(queue.len(), data.len() - 30);

        let mut slices = [IoSlice::new(&[]); 8];
        let count = queue.front_slices(&mut slices);
        let joined: Vec<u8> = slices[..count]
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect();
        assert_eq!(joined, data[30..]);

        let mut spare: [IoSliceMut<'_>; 4] = std::array::from_fn(|_| IoSliceMut::new(&mut []));
        queue.spare_slices(&pool, 4 * CHUNK, &mut spare);
        queue.commit(&pool, 0);
        assert_eq!(pool.cached(), 3);
        queue.consume(&pool, queue.len());
        assert!(queue.is_empty());
        assert_eq!(pool.cached(), 6);
    }

    #[test]
    fn reassembly_merges_and_reports_latest_first() {
        let mut ooo = Reassembly::default();
        assert!(ooo.insert(Seq(200), &[2; 100]));
        assert!(ooo.insert(Seq(400), &[4; 100]));
        assert!(!ooo.insert(Seq(420), &[4; 10]));
        let mut blocks = Vec::new();
        ooo.sack_blocks(&mut blocks, 3);
        assert_eq!(blocks, [(Seq(400), Seq(500)), (Seq(200), Seq(300))]);
        assert!(ooo.insert(Seq(250), &[3; 200]));
        assert_eq!(ooo.bytes(), 300);
        ooo.sack_blocks(&mut blocks, 3);
        assert_eq!(blocks, [(Seq(200), Seq(500))]);
        assert!(ooo.take_ready(Seq(100)).is_none());
        let ready = ooo.take_ready(Seq(220)).unwrap();
        assert_eq!(ready.len(), 280);
        assert_eq!(ready[0], 2);
        assert_eq!(ready[100], 3);
        assert!(ooo.is_empty());
        assert_eq!(ooo.bytes(), 0);
    }

    #[test]
    fn reassembly_wraps_the_sequence_space() {
        let mut ooo = Reassembly::default();
        let base = Seq(u32::MAX - 50);
        assert!(ooo.insert(base + 100, &[1; 100]));
        assert!(ooo.insert(base + 10, &[0; 90]));
        assert_eq!(ooo.take_ready(base + 10).unwrap().len(), 190);
    }

    #[test]
    fn reassembly_grows_a_range_in_place_when_segments_follow_it() {
        let mut ooo = Reassembly::default();
        let segment = [7u8; 1460];
        let mut capacity = 0;
        let mut reallocations = 0;
        for index in 0..1000u32 {
            assert!(ooo.insert(Seq(1000 + index * 1460), &segment));
            let held = ooo.ranges[0].1.capacity();
            if held != capacity {
                capacity = held;
                reallocations += 1;
            }
        }
        assert_eq!(ooo.ranges.len(), 1);
        assert_eq!(ooo.bytes(), 1000 * 1460);
        assert!(reallocations <= 12, "{reallocations} reallocations");
    }

    #[test]
    fn reassembly_matches_a_byte_map() {
        const SPAN: u32 = 6000;
        let base = Seq(u32::MAX - 2000);
        let byte = |offset: u32| (offset.wrapping_mul(2_654_435_761) >> 24) as u8;
        let mut state = 0x2545_f491_u32;
        let mut next = |bound: u32| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state % bound
        };
        for _ in 0..50 {
            let mut ooo = Reassembly::default();
            let mut held = vec![false; SPAN as usize];
            for _ in 0..200 {
                let offset = 1 + next(SPAN - 400);
                let len = 1 + next(300);
                let data: Vec<u8> = (offset..offset + len).map(byte).collect();
                let range = offset as usize..(offset + len) as usize;
                let runs = runs_of(&held);
                let touches = held[range.start - 1..=range.end].iter().any(|h| *h);
                let covered = held[range.clone()].iter().all(|h| *h);
                let stored = ooo.insert(base + offset, &data);
                if covered || (!touches && runs.len() >= MAX_RANGES) {
                    assert!(!stored);
                    continue;
                }
                assert!(stored);
                held[range].fill(true);
            }
            let runs = runs_of(&held);
            assert_eq!(ooo.bytes(), held.iter().filter(|h| **h).count());
            let mut blocks = Vec::new();
            ooo.sack_blocks(&mut blocks, MAX_RANGES);
            blocks.sort_by_key(|(start, _)| start.since(base));
            let expected: Vec<_> = runs
                .iter()
                .map(|&(start, stop)| (base + start, base + stop))
                .collect();
            assert_eq!(blocks, expected);
            for (start, stop) in runs {
                let ready = ooo.take_ready(base + start).unwrap();
                assert_eq!(ready, (start..stop).map(byte).collect::<Vec<_>>());
            }
            assert!(ooo.is_empty());
        }
    }

    fn runs_of(held: &[bool]) -> Vec<(u32, u32)> {
        let mut runs = Vec::new();
        let mut start = None;
        for (at, h) in held.iter().chain([&false]).enumerate() {
            match (start, *h) {
                (None, true) => start = Some(at as u32),
                (Some(s), false) => {
                    runs.push((s, at as u32));
                    start = None;
                }
                _ => {}
            }
        }
        runs
    }
}

use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h3::error::StreamError;
use tokio::io::ReadBuf;

pub type RecvStream = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

/// The response body of a request stream as a byte stream. A read copies every DATA chunk already
/// received until the buffer is full, as quic-go's `ReceiveStream.Read` copies all queued STREAM
/// frames (`receive_stream.go:173-226` at `2548683b`); h3-quinn yields a chunk per QUIC packet.
pub struct H3Reader {
    recv: RecvStream,
    pending: Bytes,
    end: Option<Result<(), StreamError>>,
}

impl H3Reader {
    pub fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            pending: Bytes::new(),
            end: None,
        }
    }

    /// `Ready(Ok(()))` with nothing read is the end of the body. An error that follows bytes
    /// already copied is returned by the next read.
    pub fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), StreamError>> {
        let recv = &mut self.recv;
        poll_fill(cx, out, &mut self.pending, &mut self.end, |cx| {
            recv.poll_recv_data(cx)
                .map_ok(|data| data.map(|mut data| data.copy_to_bytes(data.remaining())))
        })
    }
}

fn poll_fill<E>(
    cx: &mut Context<'_>,
    out: &mut ReadBuf<'_>,
    pending: &mut Bytes,
    end: &mut Option<Result<(), E>>,
    mut next: impl FnMut(&mut Context<'_>) -> Poll<Result<Option<Bytes>, E>>,
) -> Poll<Result<(), E>> {
    let start = out.filled().len();
    while out.remaining() != 0 {
        if !pending.is_empty() {
            let len = out.remaining().min(pending.len());
            out.put_slice(&pending.split_to(len));
            continue;
        }
        if end.is_some() {
            break;
        }
        match next(cx) {
            Poll::Ready(Ok(Some(data))) => *pending = data,
            Poll::Ready(Ok(None)) => *end = Some(Ok(())),
            Poll::Ready(Err(error)) => *end = Some(Err(error)),
            Poll::Pending if out.filled().len() > start => break,
            Poll::Pending => return Poll::Pending,
        }
    }
    if out.filled().len() == start && matches!(end, Some(Err(_))) {
        return Poll::Ready(end.replace(Ok(())).unwrap_or(Ok(())));
    }
    Poll::Ready(Ok(()))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::task::Waker;

    use super::*;

    type Step = Poll<Result<Option<Bytes>, &'static str>>;

    struct Source {
        steps: VecDeque<Step>,
        pending: Bytes,
        end: Option<Result<(), &'static str>>,
        polls: usize,
    }

    impl Source {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                pending: Bytes::new(),
                end: None,
                polls: 0,
            }
        }

        fn read(&mut self, capacity: usize) -> Poll<Result<Vec<u8>, &'static str>> {
            let mut storage = vec![0; capacity];
            let mut out = ReadBuf::new(&mut storage);
            let mut cx = Context::from_waker(Waker::noop());
            let steps = &mut self.steps;
            let polls = &mut self.polls;
            let polled = poll_fill(&mut cx, &mut out, &mut self.pending, &mut self.end, |_| {
                *polls += 1;
                steps.pop_front().unwrap_or(Poll::Pending)
            });
            polled.map_ok(|()| out.filled().to_vec())
        }
    }

    fn chunk(bytes: &'static [u8]) -> Step {
        Poll::Ready(Ok(Some(Bytes::from_static(bytes))))
    }

    #[test]
    fn a_read_takes_every_ready_chunk() {
        let mut source = Source::new([chunk(b"ab"), chunk(b"cd"), chunk(b"ef")]);
        assert_eq!(source.read(64), Poll::Ready(Ok(b"abcdef".to_vec())));
        assert_eq!(source.read(64), Poll::Pending);
    }

    #[test]
    fn a_full_buffer_keeps_the_rest_for_the_next_read() {
        let mut source = Source::new([chunk(b"abc"), chunk(b"def")]);
        assert_eq!(source.read(4), Poll::Ready(Ok(b"abcd".to_vec())));
        assert_eq!(source.polls, 2);
        assert_eq!(source.read(4), Poll::Ready(Ok(b"ef".to_vec())));
    }

    #[test]
    fn end_of_body_follows_the_last_bytes_without_another_poll() {
        let mut source = Source::new([chunk(b"ab"), Poll::Ready(Ok(None))]);
        assert_eq!(source.read(64), Poll::Ready(Ok(b"ab".to_vec())));
        assert_eq!(source.read(64), Poll::Ready(Ok(Vec::new())));
        assert_eq!(source.read(64), Poll::Ready(Ok(Vec::new())));
        assert_eq!(source.polls, 2);
    }

    #[test]
    fn an_error_after_bytes_is_returned_by_the_next_read() {
        let mut source = Source::new([chunk(b"ab"), Poll::Ready(Err("reset"))]);
        assert_eq!(source.read(64), Poll::Ready(Ok(b"ab".to_vec())));
        assert_eq!(source.read(64), Poll::Ready(Err("reset")));
        assert_eq!(source.read(64), Poll::Ready(Ok(Vec::new())));
        assert_eq!(source.polls, 2);
    }

    #[test]
    fn an_empty_buffer_reads_nothing() {
        let mut source = Source::new([chunk(b"ab")]);
        assert_eq!(source.read(0), Poll::Ready(Ok(Vec::new())));
        assert_eq!(source.polls, 0);
    }
}

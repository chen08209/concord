use std::io;
use std::ops::Deref;
use std::path::Path;
#[cfg(unix)]
use std::ptr::NonNull;

/// A file's contents as bytes, mapped read-only where the platform allows it.
///
/// On unix the pages are the page cache's own, so they cost no heap and are shared with
/// every other mapping of the file. Elsewhere the file is read onto the heap: Windows does
/// not let a file with a mapped view be replaced, and the updater replaces by rename.
///
/// A replacement by rename leaves a mapping on the old inode. Truncating or rewriting the
/// file in place changes what a mapping reads, and a truncation makes a read past the new
/// end fault.
pub struct MappedFile(Inner);

enum Inner {
    Empty,
    #[cfg(unix)]
    Mapped(NonNull<u8>, usize),
    Heap(Vec<u8>),
}

// SAFETY: the mapping is read-only and owned exclusively, like a `Box<[u8]>`.
unsafe impl Send for MappedFile {}
// SAFETY: shared access only reads through `&[u8]`.
unsafe impl Sync for MappedFile {}

impl MappedFile {
    pub fn open(path: &Path) -> io::Result<MappedFile> {
        MappedFile::from_file(&std::fs::File::open(path)?)
    }

    /// [`MappedFile::open`] for a file already open, which is left at its start.
    pub fn from_file(file: &std::fs::File) -> io::Result<MappedFile> {
        use std::io::{Read as _, Seek as _};

        let len = file.metadata()?.len();
        if len == 0 {
            return Ok(MappedFile(Inner::Empty));
        }
        #[cfg(unix)]
        if let Some(inner) = map(file, len) {
            return Ok(MappedFile(inner));
        }
        let mut reader = file;
        reader.rewind()?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        reader.rewind()?;
        Ok(MappedFile(Inner::Heap(bytes)))
    }

    /// Whether the bytes are a file mapping rather than a heap copy.
    pub fn is_mapped(&self) -> bool {
        match &self.0 {
            #[cfg(unix)]
            Inner::Mapped(..) => true,
            _ => false,
        }
    }
}

/// [`MappedFile::open`] as the type a byte-source consumer stores.
pub fn open_read_only(path: &Path) -> io::Result<Box<dyn AsRef<[u8]> + Send + Sync>> {
    MappedFile::open(path).map(|file| Box::new(file) as Box<dyn AsRef<[u8]> + Send + Sync>)
}

#[cfg(unix)]
fn map(file: &std::fs::File, len: u64) -> Option<Inner> {
    use std::os::fd::AsRawFd;

    let len = usize::try_from(len).ok()?;
    // SAFETY: a fresh read-only private mapping of an open descriptor aliases no Rust
    // object, and the mapping outlives the descriptor.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        return None;
    }
    NonNull::new(addr.cast()).map(|ptr| Inner::Mapped(ptr, len))
}

impl Deref for MappedFile {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match &self.0 {
            Inner::Empty => &[],
            #[cfg(unix)]
            // SAFETY: the mapping is `len` readable bytes owned by `self` until it drops.
            Inner::Mapped(ptr, len) => unsafe { std::slice::from_raw_parts(ptr.as_ptr(), *len) },
            Inner::Heap(bytes) => bytes,
        }
    }
}

impl AsRef<[u8]> for MappedFile {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

#[cfg(unix)]
impl Drop for MappedFile {
    fn drop(&mut self) {
        if let Inner::Mapped(ptr, len) = &self.0 {
            // SAFETY: the range is the mapping made in `map`, unmapped once.
            unsafe {
                libc::munmap(ptr.as_ptr().cast(), *len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn open_reads_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(&dir, "db", b"0123456789");
        let map = MappedFile::open(&path).unwrap();
        assert_eq!(&*map, b"0123456789");
        assert_eq!(
            map.is_mapped(),
            cfg!(unix),
            "mapped on unix, heap elsewhere"
        );
    }

    #[test]
    fn an_empty_file_is_an_empty_slice() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(&dir, "db", b"");
        let map = MappedFile::open(&path).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(MappedFile::open(&dir.path().join("none")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_rename_over_the_file_leaves_the_open_mapping_on_the_old_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(&dir, "db", b"old contents");
        let old = MappedFile::open(&path).unwrap();
        let staged = file(&dir, "db.tmp", b"new contents, longer");
        std::fs::rename(&staged, &path).unwrap();
        let new = MappedFile::open(&path).unwrap();
        assert_eq!(&*old, b"old contents");
        assert_eq!(&*new, b"new contents, longer");
        assert!(old.is_mapped() && new.is_mapped());
    }
}

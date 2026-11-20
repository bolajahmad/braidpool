use std::{
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub const SECRET_FILE_MODE: u32 = 0o400;

/// Read the secret key located at `path`, or create it with `generate`
///
/// Will return the secret_bytes and `true`, if it had to be created.
/// If another process creates the file concurrently, this call reads instead.
pub fn read_or_create_secret(
    path: &Path,
    generate: impl FnOnce() -> io::Result<Vec<u8>>,
) -> io::Result<(Vec<u8>, bool)> {
    if let Some(bytes) = read_existing(path)? {
        return Ok((bytes, false));
    }

    let secret = generate()?;
    match write_new_secret(path, &secret) {
        Ok(()) => Ok((secret, true)),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => match read_existing(path)? {
            Some(bytes) => Ok((bytes, false)),
            None => Err(io::Error::new(
                ErrorKind::NotFound,
                format!("{} disappeared while being created", path.display()),
            )),
        },
        Err(e) => Err(e),
    }
}

fn read_existing(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !meta.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("{} exists but is not a regular file", path.display()),
        ));
    }
    restrict_permissions(path, &meta)?;
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path, meta: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    if mode != SECRET_FILE_MODE {
        use tracing::warn;

        warn!(
            path = %path.display(),
            mode = format!("{mode:o}"),
            "Secret file permissions are not 0o400; tightening them"
        );
        let mut perms = meta.permissions();
        perms.set_mode(SECRET_FILE_MODE);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path, _meta: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

fn open_new(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(SECRET_FILE_MODE);
    }
    opts.open(path)
}

/// Process-wide counter so concurrent callers never pick the same temporary name, even when
/// the clock resolution is too coarse to tell their timestamps apart.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Sibling path used while the secret is being written. Unique per call.
fn temp_sibling(path: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".tmp-{}-{nanos}-{n}", std::process::id()));
    path.with_file_name(name)
}
fn write_all_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = open_new(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn write_temp(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    let mut last = None;
    for _ in 0..8 {
        let tmp = temp_sibling(path);
        match write_all_synced(&tmp, bytes) {
            Ok(()) => return Ok(tmp),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("could not create a temporary file")))
}

fn write_new_secret(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = write_temp(path, bytes)?;
    let published = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    match published {
        Ok(()) => {
            sync_parent(path);
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(e),
        Err(_) => {
            write_all_synced(path, bytes)?;
            sync_parent(path);
            Ok(())
        }
    }
}

fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

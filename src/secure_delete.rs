//! Best-effort secure deletion: overwrite file contents with random bytes
//! before unlinking, so the plaintext does not linger on disk as recoverable
//! slack space. This is not a guarantee against forensic recovery on
//! wear-levelled SSDs, but it is strictly better than a plain delete and
//! costs nothing extra the user has to think about.

use rand::RngCore;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use walkdir::WalkDir;

fn overwrite_file(path: &Path) -> std::io::Result<()> {
    let len = std::fs::metadata(path)?.len();
    if len == 0 {
        return Ok(());
    }
    let mut file = OpenOptions::new().write(true).open(path)?;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut remaining = len;
    file.seek(SeekFrom::Start(0))?;
    while remaining > 0 {
        let chunk = remaining.min(buf.len() as u64) as usize;
        rand::thread_rng().fill_bytes(&mut buf[..chunk]);
        file.write_all(&buf[..chunk])?;
        remaining -= chunk as u64;
    }
    file.sync_all()?;
    Ok(())
}

/// Overwrites and deletes a single file.
pub fn shred_file(path: &Path) -> std::io::Result<()> {
    overwrite_file(path)?;
    std::fs::remove_file(path)
}

/// Overwrites every regular file inside a folder, then removes the folder.
pub fn shred_folder(path: &Path) -> std::io::Result<()> {
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let _ = overwrite_file(entry.path());
        }
    }
    std::fs::remove_dir_all(path)
}

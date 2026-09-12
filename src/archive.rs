//! Packs a folder into a flat, sequential stream and unpacks it again.
//!
//! This intentionally isn't zip: zip's central directory sits at the end of
//! the file and needs random access to read back, which would force us to
//! fully decrypt a vault to a temp file before we could extract anything
//! (that's exactly what made large folders slow and made the progress bar
//! sit at 0% during decompression and then jump to 100%). A plain forward
//! stream lets `worker.rs` pipe folder contents straight into
//! `crypto::EncryptingWriter` and straight back out of
//! `crypto::DecryptingReader`, one pass, no temp files, no compression
//! (nothing here is worth spending CPU trying to shrink - most of what
//! people encrypt is already-compressed media anyway).
//!
//! Layout: a sequence of entries, no explicit count or terminator - the
//! reader just keeps going until the underlying stream hits EOF.
//!   entry tag   1 byte     1 = directory, 2 = file
//!   path_len    4 bytes    LE, length of the relative path below
//!   path        path_len bytes, UTF-8, '/'-separated, rooted at the folder name
//!   [file only] size       8 bytes LE
//!   [file only] content    size bytes, verbatim

use crate::crypto::DecryptingReader;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use walkdir::WalkDir;

const DIR_TAG: u8 = 1;
const FILE_TAG: u8 = 2;
const COPY_BUF_LEN: usize = 256 * 1024;

/// Sums the size of every regular file under `folder`, used up front to
/// show a sane total on the progress bar.
pub fn total_size(folder: &Path) -> u64 {
    WalkDir::new(folder)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

pub fn write_folder_stream<W: Write>(folder: &Path, out: &mut W) -> std::io::Result<()> {
    let root_name = folder.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

    for entry in WalkDir::new(folder).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let relative = path.strip_prefix(folder).unwrap();
        if relative.as_os_str().is_empty() {
            continue; // the root folder itself, nothing to record
        }
        let name = format!("{root_name}/{}", relative.to_string_lossy().replace('\\', "/"));
        let name_bytes = name.as_bytes();

        if entry.file_type().is_dir() {
            out.write_all(&[DIR_TAG])?;
            out.write_all(&(name_bytes.len() as u32).to_le_bytes())?;
            out.write_all(name_bytes)?;
        } else if entry.file_type().is_file() {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.write_all(&[FILE_TAG])?;
            out.write_all(&(name_bytes.len() as u32).to_le_bytes())?;
            out.write_all(name_bytes)?;
            out.write_all(&size.to_le_bytes())?;

            let mut f = File::open(path)?;
            std::io::copy(&mut f, out)?;
        }
        // symlinks and anything else weird are silently skipped, same as the
        // original tool did by only ever handling files and directories.
    }

    Ok(())
}

/// Reads entries back out of `input` and recreates them under
/// `destination_parent`. `on_progress` is called with `(ciphertext bytes
/// consumed so far, total ciphertext bytes)` after every chunk of file
/// content, which is what actually moves the app's progress bar.
pub fn read_folder_stream<R: Read>(
    input: &mut DecryptingReader<R>,
    destination_parent: &Path,
    total_ciphertext_len: u64,
    mut on_progress: impl FnMut(u64, u64),
) -> std::io::Result<()> {
    let mut buf = vec![0u8; COPY_BUF_LEN];

    loop {
        let mut tag = [0u8; 1];
        let n = read_or_eof(input, &mut tag)?;
        if n == 0 {
            break; // clean end of stream
        }

        let path_len = read_u32(input)? as usize;
        let mut path_bytes = vec![0u8; path_len];
        input.read_exact(&mut path_bytes)?;
        let relative = String::from_utf8(path_bytes).map_err(|_| bad_data("non-UTF-8 path in vault"))?;
        let out_path = destination_parent.join(&relative);

        match tag[0] {
            DIR_TAG => {
                std::fs::create_dir_all(&out_path)?;
            }
            FILE_TAG => {
                let size = read_u64(input)?;
                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut out_file = File::create(&out_path)?;

                let mut remaining = size;
                while remaining > 0 {
                    let chunk = remaining.min(buf.len() as u64) as usize;
                    input.read_exact(&mut buf[..chunk])?;
                    out_file.write_all(&buf[..chunk])?;
                    remaining -= chunk as u64;
                    on_progress(input.ciphertext_consumed(), total_ciphertext_len);
                }
            }
            _ => return Err(bad_data("unknown entry type in vault")),
        }
    }

    Ok(())
}

fn read_or_eof<R: Read>(r: &mut R, buf: &mut [u8; 1]) -> std::io::Result<usize> {
    match r.read(buf) {
        Ok(n) => Ok(n),
        Err(e) => Err(e),
    }
}

fn read_u32<R: Read>(r: &mut R) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64<R: Read>(r: &mut R) -> std::io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn bad_data(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

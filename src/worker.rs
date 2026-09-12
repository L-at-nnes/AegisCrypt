//! Ties the crypto core and the archive format to the filesystem: given a
//! path and a password, produce a `.aegis` vault (or restore one), deleting
//! the plaintext original on success. This runs on a background thread
//! spawned from `app.rs` - everything here is plain blocking I/O.

use crate::archive;
use crate::crypto::{self, DecryptingReader, EncryptingWriter, Kind};
use crate::secure_delete;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

pub const VAULT_EXTENSION: &str = "aegis";
const COPY_BUF_LEN: usize = 256 * 1024;

pub fn is_vault(path: &Path) -> bool {
    path.extension().map(|e| e.eq_ignore_ascii_case(VAULT_EXTENSION)).unwrap_or(false)
}

/// A handful of OS-critical locations we refuse to touch, so a careless
/// drag-and-drop can't take out a system folder. Downloads/Desktop are
/// exempted since they live under the user's own profile.
pub fn guard_critical_path(path: &Path) -> Result<(), String> {
    let mut critical: Vec<PathBuf> = vec![
        PathBuf::from(r"C:\Windows"),
        PathBuf::from(r"C:\Program Files"),
        PathBuf::from(r"C:\Program Files (x86)"),
        PathBuf::from(r"C:\ProgramData"),
        PathBuf::from(r"C:\$Recycle.Bin"),
        PathBuf::from(r"C:\System Volume Information"),
    ];
    if let Some(home) = dirs::home_dir() {
        critical.push(home);
    }
    if let Some(appdata) = dirs::data_dir() {
        critical.push(appdata);
    }
    if let Some(docs) = dirs::document_dir() {
        critical.push(docs);
    }

    let exempt: Vec<PathBuf> = [dirs::download_dir(), dirs::desktop_dir()].into_iter().flatten().collect();

    let path_lower = path.to_string_lossy().to_lowercase();
    if exempt.iter().any(|e| path_lower.starts_with(&e.to_string_lossy().to_lowercase())) {
        return Ok(());
    }
    for c in &critical {
        let c_lower = c.to_string_lossy().to_lowercase();
        if path_lower == c_lower || path_lower.starts_with(&format!("{c_lower}\\")) {
            return Err(format!(
                "\"{}\" is inside a protected system location and cannot be encrypted or decrypted.",
                path.display()
            ));
        }
    }
    Ok(())
}

fn temp_sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

// 'static because encrypt_path/decrypt_path hand a copy of it into
// EncryptingWriter/the copy loop, which may outlive the call that built it.
pub type ProgressFn = Box<dyn FnMut(u64, u64) + 'static>;

pub fn encrypt_path(target: &Path, password: &[u8], mut on_progress: ProgressFn) -> Result<PathBuf, String> {
    guard_critical_path(target)?;

    if target.is_file() {
        let final_path = target.with_extension(VAULT_EXTENSION);
        let temp_path = temp_sibling(&final_path, ".tmp");
        let extension = target.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
        let total = std::fs::metadata(target).map_err(|e| e.to_string())?.len();

        let mut input = BufReader::new(File::open(target).map_err(|e| e.to_string())?);
        let output = BufWriter::new(File::create(&temp_path).map_err(|e| e.to_string())?);

        let mut writer = EncryptingWriter::new(output, password, Kind::File, &extension).map_err(|e| e.to_string())?;
        writer.on_progress(move |written| on_progress(written, total));
        let copy_result = std::io::copy(&mut input, &mut writer).map_err(|e| e.to_string());
        let finish_result = copy_result.and_then(|_| writer.finish().map_err(|e| e.to_string()));

        if let Err(e) = finish_result {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }

        secure_delete::shred_file(target).map_err(|e| e.to_string())?;
        std::fs::rename(&temp_path, &final_path).map_err(|e| e.to_string())?;
        Ok(final_path)
    } else if target.is_dir() {
        let final_path = target.with_extension(VAULT_EXTENSION);
        let temp_path = temp_sibling(&final_path, ".tmp");
        let total = archive::total_size(target);

        let output = BufWriter::new(File::create(&temp_path).map_err(|e| e.to_string())?);
        let mut writer = EncryptingWriter::new(output, password, Kind::Folder, "").map_err(|e| e.to_string())?;
        writer.on_progress(move |written| on_progress(written, total));

        let result = archive::write_folder_stream(target, &mut writer)
            .map_err(|e| e.to_string())
            .and_then(|_| writer.finish().map_err(|e| e.to_string()));

        if let Err(e) = result {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }

        secure_delete::shred_folder(target).map_err(|e| e.to_string())?;
        std::fs::rename(&temp_path, &final_path).map_err(|e| e.to_string())?;
        Ok(final_path)
    } else {
        Err(format!("\"{}\" does not exist.", target.display()))
    }
}

pub fn decrypt_path(target: &Path, password: &[u8], mut on_progress: ProgressFn) -> Result<PathBuf, String> {
    guard_critical_path(target)?;

    let file_len = std::fs::metadata(target).map_err(|e| e.to_string())?.len();
    let input = BufReader::new(File::open(target).map_err(|e| e.to_string())?);
    let mut reader = DecryptingReader::new(input, password).map_err(|e| e.to_string())?;

    // Body length = file size minus the header we just read (fixed fields
    // plus the extension string) - used only as the progress bar's total.
    let header_len = 4 + 2 + crypto::SALT_LEN + crypto::BASE_NONCE_LEN + 1 + reader.extension().len();
    let body_len = file_len.saturating_sub(header_len as u64);

    match reader.kind() {
        Kind::File => {
            let extension = reader.extension().to_string();
            let final_path = if extension.is_empty() { target.with_extension("") } else { target.with_extension(&extension) };
            let temp_path = temp_sibling(&final_path, ".tmp");

            let mut output = BufWriter::new(File::create(&temp_path).map_err(|e| e.to_string())?);
            let result = copy_with_progress(&mut reader, &mut output, body_len, &mut on_progress)
                .and_then(|_| output.flush())
                .map_err(|e| e.to_string());

            if let Err(e) = result {
                let _ = std::fs::remove_file(&temp_path);
                return Err(e);
            }

            std::fs::remove_file(target).map_err(|e| e.to_string())?;
            std::fs::rename(&temp_path, &final_path).map_err(|e| e.to_string())?;
            Ok(final_path)
        }
        Kind::Folder => {
            let final_path = target.with_extension("");
            let destination_parent = final_path.parent().unwrap_or_else(|| Path::new("."));

            archive::read_folder_stream(&mut reader, destination_parent, body_len, |done, total| on_progress(done, total))
                .map_err(|e| e.to_string())?;

            std::fs::remove_file(target).map_err(|e| e.to_string())?;
            Ok(final_path)
        }
    }
}

fn copy_with_progress<R: Read>(
    reader: &mut DecryptingReader<R>,
    writer: &mut impl Write,
    total: u64,
    on_progress: &mut dyn FnMut(u64, u64),
) -> std::io::Result<()> {
    let mut buf = vec![0u8; COPY_BUF_LEN];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        on_progress(reader.ciphertext_consumed(), total);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aegiscrypt-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn file_roundtrip_deletes_original_and_restores_content() {
        let dir = scratch_dir("file");
        let original = dir.join("secret.txt");
        std::fs::write(&original, b"the launch code is 1234").unwrap();

        let vault = encrypt_path(&original, b"correct horse battery staple", Box::new(|_, _| {})).unwrap();
        assert!(!original.exists(), "plaintext must be gone after encryption");
        assert!(is_vault(&vault));

        let restored = decrypt_path(&vault, b"correct horse battery staple", Box::new(|_, _| {})).unwrap();
        assert!(!vault.exists(), "vault must be gone after decryption");
        assert_eq!(restored, original);
        assert_eq!(std::fs::read(&restored).unwrap(), b"the launch code is 1234");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn folder_roundtrip_preserves_structure() {
        let dir = scratch_dir("folder");
        let target = dir.join("payload");
        std::fs::create_dir_all(target.join("nested")).unwrap();
        std::fs::write(target.join("a.txt"), b"file a").unwrap();
        std::fs::write(target.join("nested/b.txt"), b"file b").unwrap();

        let vault = encrypt_path(&target, b"another-strong-pw", Box::new(|_, _| {})).unwrap();
        assert!(!target.exists());

        let restored = decrypt_path(&vault, b"another-strong-pw", Box::new(|_, _| {})).unwrap();
        assert_eq!(restored, target);
        assert_eq!(std::fs::read(restored.join("a.txt")).unwrap(), b"file a");
        assert_eq!(std::fs::read(restored.join("nested/b.txt")).unwrap(), b"file b");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn folder_roundtrip_survives_larger_content() {
        // Nothing exotic, just big enough to cross several 64 KiB stream
        // chunks in both the encrypt and decrypt direction.
        let dir = scratch_dir("bigfolder");
        let target = dir.join("payload");
        std::fs::create_dir_all(&target).unwrap();
        let big = vec![0x5Au8; 500_000];
        std::fs::write(target.join("big.bin"), &big).unwrap();
        std::fs::write(target.join("small.txt"), b"tiny").unwrap();

        let vault = encrypt_path(&target, b"pw", Box::new(|_, _| {})).unwrap();
        let restored = decrypt_path(&vault, b"pw", Box::new(|_, _| {})).unwrap();
        assert_eq!(std::fs::read(restored.join("big.bin")).unwrap(), big);
        assert_eq!(std::fs::read(restored.join("small.txt")).unwrap(), b"tiny");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_password_leaves_vault_intact() {
        let dir = scratch_dir("wrongpw");
        let original = dir.join("data.bin");
        std::fs::write(&original, vec![9u8; 5000]).unwrap();

        let vault = encrypt_path(&original, b"right-password", Box::new(|_, _| {})).unwrap();
        let err = decrypt_path(&vault, b"wrong-password", Box::new(|_, _| {})).unwrap_err();
        assert!(!err.is_empty());
        assert!(vault.exists(), "vault must survive a failed decrypt attempt");

        std::fs::remove_dir_all(&dir).ok();
    }
}

//! The AegisCrypt container format.
//!
//! Header (little-endian):
//!   magic        4 bytes   b"AEGC"
//!   version      1 byte
//!   kind         1 byte    0 = file, 1 = folder
//!   salt         16 bytes  Argon2id salt, random per vault
//!   base_nonce   7 bytes   STREAM nonce prefix, random per vault
//!   ext_len      1 byte    length of the original extension (0 for folders)
//!   ext          ext_len bytes, UTF-8, no leading dot
//!   body         AES-256-GCM STREAM chunks, 64 KiB plaintext each
//!
//! The body is exposed as a plain `Write` (`EncryptingWriter`) and `Read`
//! (`DecryptingReader`) so the rest of the app can just stream bytes through
//! it without knowing anything about chunk boundaries - a single file's
//! bytes for `Kind::File`, or a whole folder walk for `Kind::Folder` (see
//! `archive.rs`). That's what lets folder encryption skip a temp zip file
//! and go disk -> cipher -> disk in one pass.
//!
//! Confidentiality: AES-256-GCM. Integrity: every chunk carries its own GCM
//! tag, and the STREAM construction (EncryptorBE32/DecryptorBE32) folds the
//! chunk index and a "is this the last one" bit into the nonce, so chunks
//! can't be reordered, dropped, duplicated, or spliced from another vault.
//! Key derivation: Argon2id with the random salt above - the password never
//! has to be typed twice for two different secrets, which the legacy tool
//! this replaces got wrong (it made the user type and remember a "salt" too,
//! which weakens rather than strengthens the scheme).

use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use std::io::{self, Read, Write};
use zeroize::Zeroize;

pub const MAGIC: &[u8; 4] = b"AEGC";
pub const VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const BASE_NONCE_LEN: usize = 7;
const CHUNK_LEN: usize = 64 * 1024;
const TAG_LEN: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    File,
    Folder,
}

impl Kind {
    fn to_byte(self) -> u8 {
        match self {
            Kind::File => 0,
            Kind::Folder => 1,
        }
    }

    fn from_byte(b: u8) -> Result<Self, CryptoError> {
        match b {
            0 => Ok(Kind::File),
            1 => Ok(Kind::Folder),
            _ => Err(CryptoError::Corrupt("unknown container kind")),
        }
    }
}

#[derive(Debug)]
pub enum CryptoError {
    Io(io::Error),
    WrongPassword,
    Corrupt(&'static str),
    UnsupportedVersion(u8),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Io(e) => write!(f, "I/O error: {e}"),
            CryptoError::WrongPassword => write!(f, "Incorrect password, or the file is corrupted."),
            CryptoError::Corrupt(msg) => write!(f, "The file is not a valid AegisCrypt vault ({msg})."),
            CryptoError::UnsupportedVersion(v) => {
                write!(f, "This vault was created by a newer version of AegisCrypt (format v{v}).")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<io::Error> for CryptoError {
    fn from(e: io::Error) -> Self {
        CryptoError::Io(e)
    }
}

// ~64 MiB / 3 passes - well above the OWASP minimum, still under half a
// second on a normal desktop CPU.
fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| CryptoError::Corrupt("invalid kdf params"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CryptoError::Corrupt("kdf failure"))?;
    Ok(key)
}

/// Wraps an output stream, writing the header on construction and then
/// buffering `write()` calls into 64 KiB plaintext chunks that get encrypted
/// and flushed to `inner` as they fill up. Call `finish()` when done - it
/// flushes whatever is left as the final (authenticated-as-last) chunk.
/// Dropping without calling `finish()` silently loses that tail.
pub struct EncryptingWriter<W: Write> {
    inner: W,
    encryptor: EncryptorBE32<Aes256Gcm>,
    buf: Vec<u8>,
    on_progress: Option<Box<dyn FnMut(u64)>>,
    written: u64,
}

impl<W: Write> EncryptingWriter<W> {
    pub fn new(mut inner: W, password: &[u8], kind: Kind, extension: &str) -> Result<Self, CryptoError> {
        let mut salt = [0u8; SALT_LEN];
        let mut base_nonce = [0u8; BASE_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut base_nonce);

        let mut key = derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
        key.zeroize();

        let ext_bytes = extension.as_bytes();
        inner.write_all(MAGIC)?;
        inner.write_all(&[VERSION, kind.to_byte()])?;
        inner.write_all(&salt)?;
        inner.write_all(&base_nonce)?;
        inner.write_all(&[ext_bytes.len() as u8])?;
        inner.write_all(ext_bytes)?;

        Ok(Self {
            inner,
            encryptor: EncryptorBE32::from_aead(cipher, (&base_nonce).into()),
            buf: Vec::with_capacity(CHUNK_LEN),
            on_progress: None,
            written: 0,
        })
    }

    pub fn on_progress(&mut self, cb: impl FnMut(u64) + 'static) {
        self.on_progress = Some(Box::new(cb));
    }

    fn flush_full_chunk(&mut self) -> io::Result<()> {
        let ct = self
            .encryptor
            .encrypt_next(self.buf.as_slice())
            .map_err(|_| io::Error::other("encryption failure"))?;
        self.inner.write_all(&ct)?;
        self.buf.clear();
        Ok(())
    }

    /// Flushes the last (possibly empty) chunk. Must be called exactly once.
    pub fn finish(mut self) -> Result<W, CryptoError> {
        let ct = self
            .encryptor
            .encrypt_last(self.buf.as_slice())
            .map_err(|_| CryptoError::Corrupt("encryption failure"))?;
        self.inner.write_all(&ct)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptingWriter<W> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let total = data.len();
        while !data.is_empty() {
            let space = CHUNK_LEN - self.buf.len();
            let take = space.min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == CHUNK_LEN {
                self.flush_full_chunk()?;
            }
        }
        self.written += total as u64;
        if let Some(cb) = &mut self.on_progress {
            cb(self.written);
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Chunks only get authenticated once we know which one is last, so
        // there's nothing meaningful to flush early - see finish().
        Ok(())
    }
}

/// The mirror of `EncryptingWriter`: reads and validates the header eagerly
/// (so `kind()`/`extension()` are available before any plaintext comes
/// out), then serves decrypted bytes through `Read` as chunks are pulled in
/// on demand from the underlying ciphertext stream.
pub struct DecryptingReader<R: Read> {
    inner: R,
    decryptor: Option<DecryptorBE32<Aes256Gcm>>,
    kind: Kind,
    extension: String,
    plaintext_buf: Vec<u8>,
    plaintext_pos: usize,
    ciphertext_consumed: u64,
}

impl<R: Read> DecryptingReader<R> {
    pub fn new(mut inner: R, password: &[u8]) -> Result<Self, CryptoError> {
        let mut magic = [0u8; 4];
        read_exact_eof(&mut inner, &mut magic, "truncated header")?;
        if &magic != MAGIC {
            return Err(CryptoError::Corrupt("bad magic"));
        }

        let mut vk = [0u8; 2];
        read_exact_eof(&mut inner, &mut vk, "truncated header")?;
        if vk[0] != VERSION {
            return Err(CryptoError::UnsupportedVersion(vk[0]));
        }
        let kind = Kind::from_byte(vk[1])?;

        let mut salt = [0u8; SALT_LEN];
        read_exact_eof(&mut inner, &mut salt, "truncated header")?;
        let mut base_nonce = [0u8; BASE_NONCE_LEN];
        read_exact_eof(&mut inner, &mut base_nonce, "truncated header")?;

        let mut ext_len = [0u8; 1];
        read_exact_eof(&mut inner, &mut ext_len, "truncated header")?;
        let mut ext_buf = vec![0u8; ext_len[0] as usize];
        read_exact_eof(&mut inner, &mut ext_buf, "truncated header")?;
        let extension = String::from_utf8(ext_buf).map_err(|_| CryptoError::Corrupt("bad extension"))?;

        let mut key = derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
        key.zeroize();

        Ok(Self {
            inner,
            decryptor: Some(DecryptorBE32::from_aead(cipher, (&base_nonce).into())),
            kind,
            extension,
            plaintext_buf: Vec::new(),
            plaintext_pos: 0,
            ciphertext_consumed: 0,
        })
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn extension(&self) -> &str {
        &self.extension
    }

    /// How many raw (ciphertext) bytes have been pulled from the underlying
    /// stream so far - handy for a progress bar, since it tracks almost
    /// 1:1 with the vault's on-disk size regardless of chunk buffering.
    pub fn ciphertext_consumed(&self) -> u64 {
        self.ciphertext_consumed
    }

    /// Pulls and decrypts the next chunk. Returns `false` once the stream's
    /// final chunk has been consumed.
    fn pull_chunk(&mut self) -> Result<bool, CryptoError> {
        let Some(decryptor) = self.decryptor.take() else {
            return Ok(false);
        };

        let mut raw = vec![0u8; CHUNK_LEN + TAG_LEN];
        let n = read_full(&mut self.inner, &mut raw)?;
        self.ciphertext_consumed += n as u64;

        if n == raw.len() {
            let mut decryptor = decryptor;
            let pt = decryptor.decrypt_next(&raw[..n]).map_err(|_| CryptoError::WrongPassword)?;
            self.plaintext_buf = pt;
            self.plaintext_pos = 0;
            self.decryptor = Some(decryptor);
            Ok(true)
        } else {
            let pt = decryptor.decrypt_last(&raw[..n]).map_err(|_| CryptoError::WrongPassword)?;
            self.plaintext_buf = pt;
            self.plaintext_pos = 0;
            // decryptor consumed, self.decryptor stays None: stream is over.
            Ok(!self.plaintext_buf.is_empty())
        }
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.plaintext_pos >= self.plaintext_buf.len() {
            if self.decryptor.is_none() && self.plaintext_pos != 0 {
                // We've already served the final chunk; nothing left.
                return Ok(0);
            }
            let had_more = self
                .pull_chunk()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            if !had_more && self.plaintext_buf.is_empty() {
                return Ok(0);
            }
        }
        let available = &self.plaintext_buf[self.plaintext_pos..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.plaintext_pos += n;
        Ok(n)
    }
}

fn read_exact_eof<R: Read>(r: &mut R, buf: &mut [u8], msg: &'static str) -> Result<(), CryptoError> {
    r.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            CryptoError::Corrupt(msg)
        } else {
            CryptoError::Io(e)
        }
    })
}

fn read_full<R: Read>(input: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn encrypt_to_vec(data: &[u8], password: &[u8], kind: Kind, ext: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = EncryptingWriter::new(&mut out, password, kind, ext).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap();
        out
    }

    fn decrypt_all(ct: &[u8], password: &[u8]) -> Result<(Kind, String, Vec<u8>), CryptoError> {
        let mut r = DecryptingReader::new(Cursor::new(ct), password)?;
        let mut out = Vec::new();
        r.read_to_end(&mut out).map_err(|_| CryptoError::WrongPassword)?;
        Ok((r.kind(), r.extension().to_string(), out))
    }

    #[test]
    fn roundtrip_empty() {
        let ct = encrypt_to_vec(b"", b"correct horse battery staple", Kind::File, "txt");
        let (kind, ext, pt) = decrypt_all(&ct, b"correct horse battery staple").unwrap();
        assert_eq!(kind, Kind::File);
        assert_eq!(ext, "txt");
        assert_eq!(pt, b"");
    }

    #[test]
    fn roundtrip_small() {
        let ct = encrypt_to_vec(b"hello, AegisCrypt!", b"hunter2", Kind::File, "bin");
        let (_, _, pt) = decrypt_all(&ct, b"hunter2").unwrap();
        assert_eq!(pt, b"hello, AegisCrypt!");
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let data = vec![0xABu8; CHUNK_LEN * 3 + 12345];
        let ct = encrypt_to_vec(&data, b"a very long passphrase indeed", Kind::Folder, "");
        let (kind, _, pt) = decrypt_all(&ct, b"a very long passphrase indeed").unwrap();
        assert_eq!(kind, Kind::Folder);
        assert_eq!(pt, data);
    }

    #[test]
    fn wrong_password_rejected() {
        let ct = encrypt_to_vec(b"top secret", b"right-password", Kind::File, "bin");
        let err = decrypt_all(&ct, b"wrong-password").unwrap_err();
        assert!(matches!(err, CryptoError::WrongPassword));
    }

    #[test]
    fn tampering_detected() {
        let data = vec![7u8; CHUNK_LEN + 500];
        let mut ct = encrypt_to_vec(&data, b"pw", Kind::File, "dat");
        let idx = ct.len() - 100;
        ct[idx] ^= 0xFF;
        let err = decrypt_all(&ct, b"pw").unwrap_err();
        assert!(matches!(err, CryptoError::WrongPassword));
    }

    #[test]
    fn truncated_file_rejected() {
        let data = vec![1u8; 10_000];
        let mut ct = encrypt_to_vec(&data, b"pw", Kind::File, "dat");
        ct.truncate(ct.len() - 5);
        let err = decrypt_all(&ct, b"pw").unwrap_err();
        assert!(matches!(err, CryptoError::WrongPassword | CryptoError::Corrupt(_)));
    }
}

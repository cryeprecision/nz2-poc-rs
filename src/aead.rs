use anyhow::Context;
use base64::Engine;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag, aead::AeadInOut};

use crate::util;
pub use chacha20poly1305;

pub const KEY_SIZE_BYTES: usize = size_of::<Key>();
pub const TAG_SIZE_BYTES: usize = size_of::<Tag>();
pub const NONCE_SIZE_BYTES: usize = size_of::<Nonce>();

/// Deriving the nonce from the segment index ensures that
///
/// - Each segment has a unique nonce
/// - Segments cannot be reordered
/// - Nonces do not need to be stored explicitly
pub fn derive_nonce(segment_index: u64) -> Nonce {
    let mut buffer = [0u8; NONCE_SIZE_BYTES];
    buffer[..8].copy_from_slice(&segment_index.to_le_bytes());
    buffer.into()
}

/// Including these fields in the associated data protects against
///
/// - Changing the total number of segments (removing or adding segments)
/// - Changing the file path of the file (renaming cat.jpg to cat.exe)
/// - Changing the last modified timestamp of the file (if present)
pub fn derive_associated_data(
    file_size: u64,
    segment_size: u64,
    last_modified: Option<u64>,
    file_path: &str,
) -> Vec<u8> {
    let mut ad = vec![0u8; 3 * 8 + file_path.len()];
    ad[0..8].copy_from_slice(&file_size.to_le_bytes());
    ad[8..16].copy_from_slice(&segment_size.to_le_bytes());
    ad[16..24].copy_from_slice(&last_modified.unwrap_or(0).to_le_bytes());
    ad[24..].copy_from_slice(file_path.as_bytes());
    ad
}

pub fn decode_key_b64(key_b64: &str) -> anyhow::Result<Key> {
    let mut key_bytes = [0u8; KEY_SIZE_BYTES];
    let bytes_written = util::Base64
        .decode_slice(key_b64, &mut key_bytes)
        .context("Failed to decode base64 key")?;
    anyhow::ensure!(
        bytes_written == KEY_SIZE_BYTES,
        "Decoded key length is invalid: \
            expected {KEY_SIZE_BYTES} bytes, got {bytes_written} bytes",
    );
    Ok(key_bytes.into())
}

/// Encrypt the given plaintext segment in-place.
///
/// The plaintext buffer must have enough space **at the end**
/// to store the authentication tag.
pub fn encrypt_segment(
    aead: &ChaCha20Poly1305,
    segment_index: u64,
    associated_data: &[u8],
    plaintext: &mut [u8],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        plaintext.len() > TAG_SIZE_BYTES,
        "Plaintext segment must be larger than tag."
    );

    let (plaintext_buf, tag_buf) = plaintext.split_at_mut(plaintext.len() - TAG_SIZE_BYTES);
    let nonce = derive_nonce(segment_index);

    let tag = aead
        .encrypt_inout_detached(&nonce, associated_data, plaintext_buf.into())
        .map_err(|_| anyhow::anyhow!("Encryption failed."))?;
    tag_buf.copy_from_slice(tag.as_slice());

    Ok(())
}

/// Decrypt the given ciphertext segment in-place.
///
/// The ciphertext buffer must contain the authentication tag **at the end**.
/// The returned slice is the decrypted plaintext (excluding the tag).
pub fn decrypt_segment<'a>(
    aead: &ChaCha20Poly1305,
    segment_index: u64,
    associated_data: &[u8],
    ciphertext: &'a mut [u8],
) -> anyhow::Result<&'a [u8]> {
    anyhow::ensure!(
        ciphertext.len() > TAG_SIZE_BYTES,
        "Ciphertext segment must be larger than tag."
    );

    let (ciphertext_buf, tag_buf) = ciphertext.split_at_mut(ciphertext.len() - TAG_SIZE_BYTES);
    let tag: &Tag = (tag_buf as &[u8])
        .try_into()
        .expect("Tag slice has correct length.");
    let nonce = derive_nonce(segment_index);

    aead.decrypt_inout_detached(&nonce, associated_data, ciphertext_buf.into(), tag)
        .map_err(|_| anyhow::anyhow!("Decryption failed."))?;

    Ok(ciphertext_buf)
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::KeyInit;

    use super::*;

    const CLEARTEXT_SEGMENT_0: &[u8] = "TempleOS".as_bytes();
    const CLEARTEXT_SEGMENT_1: &[u8] = "🏆".as_bytes();

    const CIPHERTEXT_SEGMENT_0_B64: &str = "y2KKzjk0dykOgEXVeAkwA0ZLjvN46i1L";
    const CIPHERTEXT_SEGMENT_1_B64: &str = "tm95ac9OU4HG1uDROOGxRPoK4uE=";

    const FILE_SIZE: u64 = CLEARTEXT_SEGMENT_0.len() as u64 + CLEARTEXT_SEGMENT_1.len() as u64;
    const SEGMENT_SIZE: u64 = 8;
    const LAST_MODIFIED: Option<u64> = Some(420);
    const FILE_PATH: &str = "foo/bar/cool.hc";

    #[test]
    fn test_vector_encrypt_segment() {
        let key: Key = [0u8; KEY_SIZE_BYTES].into();
        let aead = ChaCha20Poly1305::new(&key);

        let mut cipher_buf_0 = CLEARTEXT_SEGMENT_0.to_vec();
        let mut cipher_buf_1 = CLEARTEXT_SEGMENT_1.to_vec();
        let associated_data =
            derive_associated_data(FILE_SIZE, SEGMENT_SIZE, LAST_MODIFIED, FILE_PATH);

        cipher_buf_0.resize(cipher_buf_0.len() + TAG_SIZE_BYTES, 0);
        encrypt_segment(&aead, 0, &associated_data, &mut cipher_buf_0)
            .expect("Encryption should succeed.");

        cipher_buf_1.resize(cipher_buf_1.len() + TAG_SIZE_BYTES, 0);
        encrypt_segment(&aead, 1, &associated_data, &mut cipher_buf_1)
            .expect("Encryption should succeed.");

        assert_eq!(util::Base64.encode(&cipher_buf_0), CIPHERTEXT_SEGMENT_0_B64);
        assert_eq!(util::Base64.encode(&cipher_buf_1), CIPHERTEXT_SEGMENT_1_B64);
    }

    #[test]
    fn test_vector_decrypt_segment() {
        let key: Key = [0u8; KEY_SIZE_BYTES].into();
        let aead = ChaCha20Poly1305::new(&key);

        let associated_data =
            &derive_associated_data(FILE_SIZE, SEGMENT_SIZE, LAST_MODIFIED, FILE_PATH);
        let mut cipher_buf_0 = util::Base64
            .decode(CIPHERTEXT_SEGMENT_0_B64)
            .expect("Base64 decode should succeed.");
        let mut cipher_buf_1 = util::Base64
            .decode(CIPHERTEXT_SEGMENT_1_B64)
            .expect("Base64 decode should succeed.");

        let plaintext_0 = decrypt_segment(&aead, 0, associated_data, &mut cipher_buf_0)
            .expect("Decryption should succeed.");
        let plaintext_1 = decrypt_segment(&aead, 1, associated_data, &mut cipher_buf_1)
            .expect("Decryption should succeed.");

        assert_eq!(plaintext_0, CLEARTEXT_SEGMENT_0);
        assert_eq!(plaintext_1, CLEARTEXT_SEGMENT_1);

        assert!(decrypt_segment(&aead, 1, associated_data, &mut cipher_buf_0).is_err());
        assert!(decrypt_segment(&aead, 0, associated_data, &mut cipher_buf_1).is_err());
    }
}

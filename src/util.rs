use std::{path, time};

use anyhow::Context;
pub use base64::engine::general_purpose::STANDARD as Base64;
use chacha20poly1305::Key;
use hkdf::Hkdf;
use rand::{Rng, SeedableRng, distr::Alphanumeric};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use tokio::fs;

use crate::aead;

/// Subkeys derived from a file key.
#[derive(Clone)]
pub struct SubKeys {
    /// Key used for segment encryption.
    pub encryption: Key,
    /// Key used for deriving article IDs.
    pub id: Key,
}

pub struct SegmentIds {
    /// Message-ID for the segment.
    pub message_id: String,
    /// Subject for the segment.
    pub subject: String,
    /// Poster for the segment.
    pub poster: String,
}

/// A-Z a-z 0-9 => 62 characters => log2(62) * (32+8+3) ≈ 256 bits of randomness
pub fn generate_id<R: Rng>(rng: &mut R) -> String {
    // Takes u32's from the underlying RNG and uses rejection sampling
    let mut rng = rng.sample_iter(Alphanumeric).map(char::from);
    let mut s = String::with_capacity(32 + 1 + 8 + 1 + 3);

    (&mut rng).take(32).for_each(|c| s.push(c));
    s.push('@');
    (&mut rng).take(8).for_each(|c| s.push(c));
    s.push('.');
    (&mut rng).take(3).for_each(|c| s.push(c));

    s
}

/// Derive a deterministic ID from the given subkeys and segment_index.
pub fn derive_id(keys: &SubKeys, segment_index: u64, kind: &[u8; 3]) -> String {
    let hkdf = Hkdf::<Sha256>::new(Some(b"nz2:1.0.0:segment"), keys.id.as_slice());

    let mut info = [0u8; 11];
    info[..8].copy_from_slice(&segment_index.to_le_bytes());
    info[8..].copy_from_slice(kind);

    let mut seed = [0u8; aead::KEY_SIZE_BYTES];
    hkdf.expand(&info, &mut seed)
        .expect("within HKDF length limits");

    let mut rng = ChaCha20Rng::from_seed(seed);
    generate_id(&mut rng)
}

/// Derives the ID to use as the poster for the given segment
pub fn derive_poster_id(keys: &SubKeys, segment_index: u64) -> String {
    derive_id(keys, segment_index, b"pos")
}

/// Derives the ID to use as the subject for the given segment
pub fn derive_subject_id(keys: &SubKeys, segment_index: u64) -> String {
    derive_id(keys, segment_index, b"sub")
}

/// Derives the ID to use as the message-id for the given segment
pub fn derive_message_id(keys: &SubKeys, segment_index: u64) -> String {
    derive_id(keys, segment_index, b"msg")
}

/// Generate a new random 32-byte file key from a CSPRNG.
pub fn generate_file_key() -> Key {
    let mut key_bytes = [0u8; aead::KEY_SIZE_BYTES];
    rand::rng().fill(&mut key_bytes);
    key_bytes.into()
}

pub fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, fmt};

    tracing_subscriber::registry()
        .with(fmt::layer().with_test_writer())
        .with(EnvFilter::from_default_env())
        .init();
}

/// Derive encryption and ID subkeys from the given file key using HKDF-SHA256.
pub fn derive_subkeys(file_key: &Key) -> SubKeys {
    let hkdf = Hkdf::<Sha256>::new(Some(b"nz2:1.0.0:file"), file_key.as_slice());

    let mut encryption = [0u8; aead::KEY_SIZE_BYTES];
    hkdf.expand(b"encrypt", &mut encryption)
        .expect("within HKDF length limits");

    let mut id = [0u8; aead::KEY_SIZE_BYTES];
    hkdf.expand(b"derive", &mut id)
        .expect("within HKDF length limits");

    SubKeys {
        encryption: encryption.into(),
        id: id.into(),
    }
}

pub async fn set_last_modified_from_unix_timestamp(
    file: fs::File,
    timestamp: u64,
) -> anyhow::Result<fs::File> {
    let system_time = time::UNIX_EPOCH
        .checked_add(time::Duration::from_secs(timestamp))
        .context("Timestamp out of range")?;

    let file = file.into_std().await;
    tokio::task::spawn_blocking(move || {
        file.set_modified(system_time)
            .context("Failed to set last modified time")?;
        Ok(fs::File::from_std(file))
    })
    .await
    .expect("task does not panic")
}

pub fn get_last_modified_as_unix_timestamp(entry: &path::Path) -> anyhow::Result<u64> {
    entry
        .metadata()
        .context("Failed to get file metadata")?
        .modified()
        .context("Failed to get file last modified time")?
        .duration_since(time::UNIX_EPOCH)
        .context("Last modified time is before UNIX_EPOCH")
        .map(|duration| duration.as_secs())
}

pub fn bar_bytes(len: u64) -> indicatif::ProgressBar {
    let style = indicatif::ProgressStyle::with_template(
        "[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({bytes_per_sec}, {eta}) {msg}",
    )
    .expect("valid progress bar template")
    .progress_chars("-> ");

    indicatif::ProgressBar::new(len).with_style(style)
}

pub fn bar_items(len: u64) -> indicatif::ProgressBar {
    let style = indicatif::ProgressStyle::with_template(
        "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta}) {msg}",
    )
    .expect("valid progress bar template")
    .progress_chars("-> ");

    indicatif::ProgressBar::new(len).with_style(style)
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use rand::RngCore;

    use super::*;

    #[test]
    fn test_deterministic_segment_ids() {
        let file_key = generate_file_key();
        let keys = derive_subkeys(&file_key);

        let segment_id_a_0 = derive_message_id(&keys, 0);
        let segment_id_a_1 = derive_message_id(&keys, 1);

        let keys = derive_subkeys(&file_key);
        let segment_id_b_0 = derive_message_id(&keys, 0);
        let segment_id_b_1 = derive_message_id(&keys, 1);

        assert_eq!(segment_id_a_0, segment_id_b_0);
        assert_eq!(segment_id_a_1, segment_id_b_1);
        assert_ne!(segment_id_a_0, segment_id_a_1);
    }

    #[test]
    fn test_vector_chacha20_rng() {
        let mut rng = ChaCha20Rng::from_seed([0x00u8; 32]);
        let mut iter = (0..).map(|_| rng.next_u32());

        let mut values = Vec::new();
        values.extend((&mut iter).take(1));
        values.extend((&mut iter).skip(4096 - 1).take(1));
        values.extend((&mut iter).skip(4096 - 1).take(1));
        values.extend((&mut iter).skip(4096 - 1).take(1));

        const EXPECTED_00: [u32; 4] = [0xade0b876, 0x385a46ee, 0x02742d22, 0x88602327];
        assert_eq!(values.as_slice(), &EXPECTED_00);

        let mut rng = ChaCha20Rng::from_seed([0xFFu8; 32]);
        let mut iter = (0..).map(|_| rng.next_u32());

        let mut values = Vec::new();
        values.extend((&mut iter).take(1));
        values.extend((&mut iter).skip(4096 - 1).take(1));
        values.extend((&mut iter).skip(4096 - 1).take(1));
        values.extend((&mut iter).skip(4096 - 1).take(1));

        const EXPECTED_FF: [u32; 4] = [0x4198b8f6, 0x2af06bd5, 0xaf06794c, 0xe88561b1];
        assert_eq!(values.as_slice(), &EXPECTED_FF);
    }

    #[test]
    fn test_vector_generate_id() {
        let mut rng = ChaCha20Rng::from_seed([0x00u8; 32]);
        let ids = (0..5).map(|_| generate_id(&mut rng)).collect::<Vec<_>>();

        const EXPECTED_00: [&str; 5] = [
            "rk5KuGzxfjPN9HahvefDoaP7dQs1KRHb@54CdmxNX.aDH",
            "EwY8WaqCIcNpgLEPVbfdr3sOK2RDyRhy@OzToRBF1.pk2",
            "yGoUdIhTCDFYMSLRjEGXmwtLTwjCz5BD@m3Xg4F21.fSB",
            "30SuoDE2uGfuZaeenpLzgOLFBYYvuBGd@wVxg8uYg.CvN",
            "wFXv20LyC2VrxCLKwYfGalM8CWHPeqMg@AV2UZSEv.ieF",
        ];
        assert_eq!(ids.as_slice(), &EXPECTED_00);

        let mut rng = ChaCha20Rng::from_seed([0xFFu8; 32]);
        let ids = (0..5).map(|_| generate_id(&mut rng)).collect::<Vec<_>>();

        const EXPECTED_FF: [&str; 5] = [
            "QYwoRsxcKX8odQMV2thkgmPyIyKGFtzU@kAUXh6Hc.tSq",
            "ne7pG9cQTbY4QBN2Z1iv7HCGlRPiNlB8@9gM51E1t.08R",
            "znIb3pt8k3ZxOotxrQCikogccz8Qqmk9@5azUhTFB.hnY",
            "wif3gteK8oqV5vEOdz09LX5IrTdcvvu5@avWh0Ymg.sIM",
            "0h3EdxTT2IxypHc1hJmYNtvJqcXofh9q@nAQAYQ1J.zdh",
        ];
        assert_eq!(ids.as_slice(), &EXPECTED_FF);
    }

    #[test]
    fn test_vector_derive_subkeys() {
        let key = Key::from([0x00u8; 32]);
        let subkeys = derive_subkeys(&key);
        assert_eq!(
            Base64.encode(&subkeys.encryption),
            "SXCHftg+g/FdRlZ6AlRRbCEPv16w7tIGXqJn74m2tSA="
        );
        assert_eq!(
            Base64.encode(&subkeys.id),
            "36/mff1sS26w2W9xIEYQ9IHerhdcbtPFwzGhmc+Koy4="
        );

        let key = Key::from([0xFFu8; 32]);
        let subkeys = derive_subkeys(&key);
        assert_eq!(
            Base64.encode(&subkeys.encryption),
            "klOlmm52VO59xVaXE0jgc7XQBetYjgz6qfbzY2Sy7Ps="
        );
        assert_eq!(
            Base64.encode(&subkeys.id),
            "lFlvUluZL/vaueafGGPaPwsJNgXpfZbgYAoc+ktmkDs="
        );
    }

    #[test]
    fn test_vector_derive_segment_ids() {
        let keys = SubKeys {
            encryption: [0x00u8; 32].into(),
            id: [0x00u8; 32].into(),
        };

        const EXPECTED_00: [(&str, &str, &str); 5] = [
            (
                "R4NAnuY181vWV0rE2vfggn0hr5ImRWXJ@E5zLU1Pl.jv4",
                "AoGbuE58MvNvGZoyXrjdvuhIuKsjjEEe@iM8MdKXu.9wX",
                "I9fkzYaGxXGOkCXl5lrnjQba3vTdPCGF@KoOhI9e0.fCw",
            ),
            (
                "csWNPuAQtp8wsCXxQGltm7X4qZrAm8rv@1XrmNxMN.gXq",
                "SKoPNIMp03N40b0M095p4yMkxIVGkdUb@I2wvGmeb.uxc",
                "6VMn8QfH1PLin2tQYWo1kAABAN6R9Qc8@LwDEWPAo.4m6",
            ),
            (
                "coyFwwSj4BHyFYyyKWEy7dSCLytpEj7D@kEv5uABo.hFw",
                "VAYhfcOPFcFCZ0REsXYzwB3O74qW6ime@oZODtXU3.HO0",
                "APUF2MBQkRewJn6qqMtRC2PpWdYYB0wq@Ko7tu2GQ.mM0",
            ),
            (
                "EzT1ZHu8LxP6LRKsfFxd5xP52HhtUTC2@gINwjMrn.ZeC",
                "nnsWRGKrtAJU7YpjYewPHlhOW5wbckFB@vdlxirvr.LQF",
                "pJJnt3ypPgLXwLLS7seHUW9FZhxsyCb6@Ib27yxsU.Ukr",
            ),
            (
                "zEvYtgoNFmfI4jTDbOGsi2LNW2no5R1q@NC5GW8mP.74u",
                "PTny0GQtsdt4DRQSyqSpgfBdxx4wxudi@GK485qeR.H5e",
                "lhnBpTIliPunTF0gMXTNYJRn2NYT2LsD@wY17YfBp.Jfr",
            ),
        ];

        let ids = (0..5)
            .map(|i| {
                (
                    derive_message_id(&keys, i),
                    derive_subject_id(&keys, i),
                    derive_poster_id(&keys, i),
                )
            })
            .collect::<Vec<_>>();

        for i in 0..5 {
            assert_eq!(EXPECTED_00[i].0, ids[i].0);
            assert_eq!(EXPECTED_00[i].1, ids[i].1);
            assert_eq!(EXPECTED_00[i].2, ids[i].2);
        }

        const EXPECTED_FF: [(&str, &str, &str); 5] = [
            (
                "l4qmBVuaUtosiHJDIkVFfNjtabtzfzgv@zmqxYgya.uY4",
                "0WisDbzc3Dhr6KQEhpF16Q0XNAfTpNNI@sByUXNzQ.v4C",
                "5U7mXSmxAG7nQoBPKOcy1iGAR15uodtW@Iqxm78W2.x4r",
            ),
            (
                "Z1tPWZzIzTb5KdVoLu3vZuj4WoB1e00b@Upw6d0hM.2BS",
                "xp6i9arqg8HXItIsxqrDuUoISscfsmbT@lInB7CgY.VOm",
                "ggZQcMIPthnlr0GqGkJOXOOUJ0oe6Xyn@tWWvXlIi.lqM",
            ),
            (
                "uSbrAmoj6APfldfgWYiGPaZG7alUgHz3@xxyG61O7.HMl",
                "mqL7UnM8zoUHbhyInjsWGWu5ljIzLIN8@GujHoMtE.fcJ",
                "brxnLUXAXG6VQnayEXvXKZ2zf8LxfTtV@tirWogbV.bxa",
            ),
            (
                "Q16sTds3rUZuerrtUHQnBA0JYA0FRQpb@Sv8rY838.2Bg",
                "oTnMMMjDULAuJ9kzfZdpK60erLkf15mh@X2AHrU7B.Icq",
                "eHYrYoSz3SAweM80pA0rX2mugs47IKsL@UITdLv1J.OCU",
            ),
            (
                "7l65irxQhCn5v4LBf2kHrru38wYz0mp1@TyC7hxEE.ZGz",
                "VFB4LLok9VegXeBRreBFrpb5DGIPmUw6@BeGt63hg.Mkj",
                "bsiP1DivzMqLaBnIL4V8cQ6pnKL0Sj52@mkEqUpK3.UtK",
            ),
        ];

        let keys = SubKeys {
            encryption: [0xFFu8; 32].into(),
            id: [0xFFu8; 32].into(),
        };

        let ids = (0..5)
            .map(|i| {
                (
                    derive_message_id(&keys, i),
                    derive_subject_id(&keys, i),
                    derive_poster_id(&keys, i),
                )
            })
            .collect::<Vec<_>>();

        for i in 0..5 {
            assert_eq!(EXPECTED_FF[i].0, ids[i].0);
            assert_eq!(EXPECTED_FF[i].1, ids[i].1);
            assert_eq!(EXPECTED_FF[i].2, ids[i].2);
        }
    }
}

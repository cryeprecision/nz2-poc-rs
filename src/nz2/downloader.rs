use std::{sync::Arc, time};

use anyhow::Context;
use async_channel::{Receiver, Sender};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use super::context::DownloadCtx;
use crate::{aead, util};

pub struct Request {
    pub ctx: Arc<DownloadCtx>,
    pub segment_index: u64,
}

pub struct Response {
    pub ctx: Arc<DownloadCtx>,
    pub segment_index: u64,
    pub data: Option<Vec<u8>>,
    pub meta: Box<ResponseMeta>,
}

pub struct ResponseMeta {
    pub elapsed_download: f64,
    pub elapsed_decode: f64,
    pub elapsed_decrypt: f64,
    pub elapsed_total: f64,
    pub bytes: u64,
    pub bytes_with_overhead: u64,
}

/// Downloads segments from NNTP server as requested from the `dl_rx` channel,
/// and forwards the downloaded data to the `dl_tx` channel.
#[tracing::instrument(level = "debug", skip(pool, dl_rx, dl_tx))]
pub async fn downloader_task(
    pool: nntp_rs::Pool,
    dl_rx: Receiver<Request>,
    dl_tx: Sender<Response>,
) -> anyhow::Result<()> {
    let mut conn = (pool.get().await).context("Failed to get NNTP connection from pool")?;
    let mut cipher_buf: Vec<u8> = Vec::new();

    while let Ok(payload) = dl_rx.recv().await {
        let start = time::Instant::now();

        cipher_buf.clear();

        let Request { ctx, segment_index } = payload;
        let message_id = util::derive_message_id(&ctx.crypto_ctx.keys, segment_index);

        let download_start = time::Instant::now();
        let article = conn
            .body(&message_id)
            .await
            .with_context(|| format!("Error downloading article {message_id}"))?;
        let elapsed_download = download_start.elapsed().as_secs_f64();

        let Some(article) = article else {
            let elapsed = start.elapsed().as_secs_f64();
            let response = Response {
                ctx,
                segment_index: payload.segment_index,
                meta: Box::new(ResponseMeta {
                    elapsed_download,
                    elapsed_decode: 0.0,
                    elapsed_decrypt: 0.0,
                    elapsed_total: elapsed,
                    bytes: 0,
                    bytes_with_overhead: 0,
                }),
                data: None,
            };

            dl_tx.send(response).await.with_context(|| {
                format!("Failed to send response for missing article {message_id}")
            })?;
            continue;
        };

        let (cipher_buf_, article, elapsed_decode, elapsed_decrypt) =
            tokio::task::spawn_blocking({
                let ctx = Arc::clone(&ctx);
                move || -> anyhow::Result<_> {
                    let DownloadCtx { crypto_ctx, .. } = ctx.as_ref();

                    let aead = ChaCha20Poly1305::new(&crypto_ctx.keys.encryption);
                    let segment_size = ctx.segment_size(segment_index) as usize;

                    let start_decode = std::time::Instant::now();
                    cipher_buf.extend_from_slice(&article);
                    rapidyenc::decode(&mut cipher_buf);
                    let elapsed_decode = start_decode.elapsed().as_secs_f64();

                    let start_decrypt = std::time::Instant::now();
                    _ = aead::decrypt_segment(
                        &aead,
                        segment_index,
                        &crypto_ctx.assoc_data,
                        &mut cipher_buf,
                    )?;
                    cipher_buf.truncate(segment_size);
                    let elapsed_decrypt = start_decrypt.elapsed().as_secs_f64();

                    Ok((cipher_buf, article, elapsed_decode, elapsed_decrypt))
                }
            })
            .await
            .expect("task does not panic")
            .with_context(|| format!("Failed to decode/decrypt segment {segment_index}"))?;

        // Reuse cipher buffer
        cipher_buf = cipher_buf_;

        // Copy out the decrypted data
        let data = Some(cipher_buf.clone());
        let elapsed_total = start.elapsed().as_secs_f64();

        let response = Response {
            ctx,
            segment_index,
            meta: Box::new(ResponseMeta {
                elapsed_download,
                elapsed_decode,
                elapsed_decrypt,
                elapsed_total,
                bytes: cipher_buf.len() as u64,
                bytes_with_overhead: article.len() as u64,
            }),
            data,
        };

        dl_tx
            .send(response)
            .await
            .with_context(|| format!("Failed to send response for article {message_id}"))?;
    }

    Ok(())
}

use std::sync::Arc;

use anyhow::Context;
use async_channel::{Receiver, Sender};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chrono::Utc;

use super::context::UploadCtx;
use crate::aead;
use crate::aead::TAG_SIZE_BYTES;
use crate::util;

pub struct Request {
    pub ctx: Arc<UploadCtx>,
    pub segment_index: u64,
    pub body: Vec<u8>,
}

pub struct Response {
    pub ctx: Arc<UploadCtx>,
    pub segment_index: u64,
    pub meta: Box<ResponseMeta>,
}

pub struct ResponseMeta {
    pub elapsed_encode: f64,
    pub elapsed_encrypt: f64,
    pub elapsed_upload: f64,
    pub elapsed_total: f64,
    pub bytes: u64,
    pub bytes_with_overhead: u64,
}

#[tracing::instrument(level = "debug", skip(pool, up_rx))]
pub async fn uploader_task(
    pool: nntp_rs::Pool,
    up_rx: Receiver<Request>,
    up_tx: Sender<Response>,
) -> anyhow::Result<()> {
    let mut conn = (pool.get().await).context("Failed to get NNTP connection from pool")?;
    let mut cipher_buf: Vec<u8> = Vec::new();

    while let Ok(payload) = up_rx.recv().await {
        let start = std::time::Instant::now();

        cipher_buf.clear();

        let Request {
            ctx,
            segment_index,
            body,
        } = payload;

        let (cipher_buf_, yenc_buf, body, elapsed_encrypt, elapsed_encode) =
            tokio::task::spawn_blocking({
                let ctx = Arc::clone(&ctx);
                move || -> anyhow::Result<_> {
                    let UploadCtx {
                        crypto_ctx,
                        yenc_ctx,
                        ..
                    } = ctx.as_ref();

                    let aead = ChaCha20Poly1305::new(&crypto_ctx.keys.encryption);

                    let start_encrypt = std::time::Instant::now();
                    cipher_buf.resize(body.len() + TAG_SIZE_BYTES, 0);
                    cipher_buf[..body.len()].copy_from_slice(&body);
                    aead::encrypt_segment(
                        &aead,
                        segment_index,
                        &crypto_ctx.assoc_data,
                        &mut cipher_buf,
                    )?;
                    let elapsed_encrypt = start_encrypt.elapsed().as_secs_f64();

                    let start_encode = std::time::Instant::now();
                    let yenc_buf = rapidyenc::encode(&cipher_buf, yenc_ctx.yenc_line_width);
                    let elapsed_encode = start_encode.elapsed().as_secs_f64();

                    Ok((cipher_buf, yenc_buf, body, elapsed_encrypt, elapsed_encode))
                }
            })
            .await
            .expect("task does not panic")
            .with_context(|| format!("Failed to encrypt/encode segment {segment_index}"))?;

        // Reuse buffer
        cipher_buf = cipher_buf_;

        let start_upload = std::time::Instant::now();
        let message_id = util::derive_message_id(&ctx.crypto_ctx.keys, segment_index);
        let subject = util::derive_subject_id(&ctx.crypto_ctx.keys, segment_index);
        let poster = util::derive_poster_id(&ctx.crypto_ctx.keys, segment_index);

        let headers = nntp_rs::ArticleHeaders {
            datetime: Utc::now(),
            from: poster,
            message_id: message_id.clone(),
            newsgroups: ctx.yenc_ctx.newsgroups.to_vec(),
            subject,
        };

        conn.post(&headers, &yenc_buf)
            .await
            .with_context(|| format!("Error posting article {message_id}"))?;
        let elapsed_upload = start_upload.elapsed().as_secs_f64();
        let elapsed = start.elapsed().as_secs_f64();

        let response = Response {
            ctx,
            segment_index,
            meta: Box::new(ResponseMeta {
                elapsed_encrypt,
                elapsed_encode,
                elapsed_upload,
                elapsed_total: elapsed,
                bytes: body.len() as u64,
                bytes_with_overhead: yenc_buf.len() as u64,
            }),
        };

        up_tx
            .send(response)
            .await
            .with_context(|| format!("Failed to send response for article {message_id}"))?;
    }
    Ok(())
}

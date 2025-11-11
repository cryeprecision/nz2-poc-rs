use std::sync::Arc;

use anyhow::Context;
use async_channel::{Receiver, Sender};
use chacha20poly1305::Key;
use indicatif::ProgressBar;

use super::{downloader, uploader};
use crate::{aead, bar, nz2, schema, util};

/// Cryptographic context for a specific file.
pub struct CryptoCtx {
    pub file_key: Key,
    pub keys: util::SubKeys,
    pub assoc_data: Arc<[u8]>,
}

/// yEnc encoding context
pub struct YencCtx {
    pub yenc_line_width: u32,
    pub article_split_size: u64,
    pub newsgroups: Vec<String>,
}

pub trait SuspendBars {
    fn bars(&self) -> &bar::MultiProgress;

    fn suspend<R, F: FnOnce() -> R>(&self, f: F) -> R {
        self.bars().suspend(f)
    }
}

/// Global context shared across files, segments, uploads, and downloads.
pub struct GlobalCtx {
    pub pool: nntp_rs::Pool,
    pub connections: usize,
    pub bars: bar::MultiProgress,
}

impl SuspendBars for GlobalCtx {
    fn bars(&self) -> &bar::MultiProgress {
        &self.bars
    }
}

pub struct DownloadCtx {
    pub global_ctx: Arc<GlobalCtx>,
    pub crypto_ctx: Arc<CryptoCtx>,
    pub files: Arc<[schema::File]>,
    pub file_index: usize,
    pub file_bar: ProgressBar,

    pub dl_tx: Sender<downloader::Request>,
    pub dl_rx: Receiver<downloader::Response>,
}

impl SuspendBars for DownloadCtx {
    fn bars(&self) -> &bar::MultiProgress {
        &self.global_ctx.bars
    }
}

impl DownloadCtx {
    pub fn new(
        global_ctx: &Arc<GlobalCtx>,
        files: &Arc<[schema::File]>,
        file_index: usize,
        dl_tx: &Sender<downloader::Request>,
        dl_rx: &Receiver<downloader::Response>,
    ) -> anyhow::Result<Arc<Self>> {
        let file = &files[file_index];

        let file_bar = global_ctx.bars.add(util::bar_bytes(file.file_size));
        file_bar.set_message(file.path.clone());

        let file_key = aead::decode_key_b64(&file.key).with_context(|| {
            format!(
                "Failed to decode file key for file {file}",
                file = file.path,
            )
        })?;
        let keys = util::derive_subkeys(&file_key);

        let assoc_data: Arc<[u8]> = aead::derive_associated_data(
            file.file_size,
            file.segment_size,
            file.last_modified,
            &file.path,
        )
        .into();

        let crypto_ctx = Arc::new(CryptoCtx {
            file_key,
            keys,
            assoc_data,
        });

        Ok(Arc::new(Self {
            global_ctx: Arc::clone(global_ctx),
            crypto_ctx,
            files: Arc::clone(files),
            file_index,
            file_bar,
            dl_tx: dl_tx.clone(),
            dl_rx: dl_rx.clone(),
        }))
    }

    pub fn suspend<R, F: FnOnce() -> R>(&self, f: F) -> R {
        self.global_ctx.bars.suspend(f)
    }

    pub fn file(&self) -> &schema::File {
        &self.files[self.file_index]
    }

    pub fn num_segments(&self) -> u64 {
        let file = self.file();
        file.file_size.div_ceil(file.segment_size)
    }

    pub fn segment_size(&self, segment_index: u64) -> u64 {
        let range = self.segment_range(segment_index);
        range.end - range.start
    }

    pub fn segment_range(&self, segment_index: u64) -> std::ops::Range<u64> {
        let file = self.file();
        let start = segment_index * file.segment_size;
        let end = std::cmp::min(start + file.segment_size, file.file_size);
        start..end
    }
}

pub struct UploadCtx {
    pub global_ctx: Arc<GlobalCtx>,
    pub crypto_ctx: Arc<CryptoCtx>,
    pub yenc_ctx: Arc<YencCtx>,

    pub files: Arc<[nz2::File]>,
    pub file_index: usize,
    pub file_bar: ProgressBar,

    pub up_tx: Sender<uploader::Request>,
    pub up_rx: Receiver<uploader::Response>,
}

impl SuspendBars for UploadCtx {
    fn bars(&self) -> &bar::MultiProgress {
        &self.global_ctx.bars
    }
}

impl UploadCtx {
    pub fn new(
        global_ctx: &Arc<GlobalCtx>,
        yenc_ctx: &Arc<YencCtx>,
        files: &Arc<[nz2::File]>,
        file_index: usize,
        up_tx: &Sender<uploader::Request>,
        up_rx: &Receiver<uploader::Response>,
    ) -> Arc<Self> {
        let file = &files[file_index];

        let file_bar = global_ctx.bars.add(util::bar_bytes(file.size));
        file_bar.set_message(file.path_rel.clone());

        let file_key = util::generate_file_key();
        let keys = util::derive_subkeys(&file_key);

        let assoc_data: Arc<[u8]> = aead::derive_associated_data(
            file.size,
            yenc_ctx.article_split_size,
            file.last_modified,
            &file.path_rel,
        )
        .into();

        let crypto_ctx = Arc::new(CryptoCtx {
            file_key,
            keys,
            assoc_data,
        });

        Arc::new(Self {
            global_ctx: Arc::clone(global_ctx),
            yenc_ctx: Arc::clone(yenc_ctx),
            crypto_ctx,
            files: Arc::clone(files),
            file_index,
            file_bar,
            up_tx: up_tx.clone(),
            up_rx: up_rx.clone(),
        })
    }

    pub fn file(&self) -> &nz2::File {
        &self.files[self.file_index]
    }

    pub fn num_segments(&self) -> u64 {
        let file = self.file();
        file.size.div_ceil(self.yenc_ctx.article_split_size)
    }
}

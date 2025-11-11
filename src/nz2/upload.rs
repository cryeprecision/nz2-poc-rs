use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use anyhow::Context;
use base64::Engine;
use futures::FutureExt;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use human_repr::HumanCount;
use human_repr::HumanDuration;
use human_repr::HumanThroughput;
use tokio::fs;
use tokio::io::AsyncReadExt;

use super::RangeChunks;
use super::context::GlobalCtx;
use super::context::SuspendBars;
use super::context::UploadCtx;
use super::uploader;
use crate::aead::TAG_SIZE_BYTES;
use crate::nz2::context::YencCtx;
use crate::{schema, util};

#[derive(Clone)]
pub struct File {
    pub path: PathBuf,
    pub path_rel: String,
    pub size: u64,
    pub last_modified: Option<u64>,
}

fn collect_files(source_dir: PathBuf) -> anyhow::Result<Vec<File>> {
    anyhow::ensure!(source_dir.is_dir(), "source_dir must be a directory");

    let source_dir = source_dir.canonicalize().with_context(|| {
        format!(
            "Failed to canonicalize source directory path: {}",
            source_dir.display()
        )
    })?;

    // iterate over all files in source_dir recursively
    let mut files_iter = walkdir::WalkDir::new(&source_dir)
        .into_iter()
        .filter_map(|entry| {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    tracing::warn!("Error reading directory entry: {:?}", err);
                    return None;
                }
            };
            entry.file_type().is_file().then_some(entry)
        });

    let mut files = Vec::<File>::new();
    let files_result = files_iter.try_for_each(|entry| -> anyhow::Result<()> {
        let path = entry
            .path()
            .canonicalize()
            .with_context(|| format!("Failed to canonicalize path: {}", entry.path().display()))?;
        tracing::debug!("Found file: {}", path.display());

        // Get the path relative to the source directory
        let path_rel = path
            .strip_prefix(&source_dir)
            .expect("We're traversing children of the source directory")
            .to_str()
            .with_context(|| format!("Path is not valid UTF-8: {}", path.display()))?;

        // Get file size
        let file_size = entry
            .metadata()
            .with_context(|| format!("Couldn't get metadata for: {}", path.display()))?
            .len();

        // Get last modified time (optional)
        let last_modified = match util::get_last_modified_as_unix_timestamp(entry.path()) {
            Ok(timestamp) => Some(timestamp),
            Err(err) => {
                tracing::warn!(
                    "Couldn't get last modified time for file {}: {err:?}",
                    path.display()
                );
                None
            }
        };

        files.push(File {
            path: path.to_owned(),
            path_rel: path_rel.to_string(),
            size: file_size,
            last_modified,
        });
        Ok(())
    });

    files_result.with_context(|| {
        format!(
            "Failed to collect files from directory: {}",
            source_dir.display()
        )
    })?;

    Ok(files)
}

async fn upload_file(ctx: Arc<UploadCtx>) -> anyhow::Result<schema::File> {
    // Open the file for reading
    let mut fs_file = fs::File::open(&ctx.file().path).await.with_context(|| {
        format!(
            "Failed to open file for reading: {path}",
            path = ctx.file().path_rel
        )
    })?;

    let num_segments = ctx.num_segments();
    let split_size = ctx.yenc_ctx.article_split_size;
    let mut read_buf = Vec::with_capacity(split_size as usize + TAG_SIZE_BYTES);

    // Keep track of how many segments are remaining to be uploaded
    // to know when we're done with the current file.
    //
    // Since the uploader tasks keep running over multiple files, we need to
    // track ourselves when all segments for this file are done.
    //
    // TODO: Segments remaining doesn't need to be atomic
    let read_times = Arc::new(Mutex::new(vec![0.0f64; num_segments as usize]));
    let segments_remaining = Arc::new(AtomicU64::new(num_segments));

    // Spawn a task to increment the progress bar based on uploader responses
    let incrementer_task = tokio::task::spawn({
        let read_times = Arc::clone(&read_times);
        let ctx = Arc::clone(&ctx);
        async move {
            while let Ok(response) = ctx.up_rx.recv().await {
                let uploader::Response {
                    ctx,
                    segment_index,
                    meta,
                } = response;

                let overhead =
                    (meta.bytes_with_overhead as f64 / meta.bytes as f64 * 100.0) - 100.0;
                let overhead_abs = (meta.bytes_with_overhead - meta.bytes) as f64;

                let elapsed_read = {
                    let read_times = read_times.lock().expect("lock holders do not panic");
                    read_times[segment_index as usize]
                };

                // Log some stats about the segment
                ctx.suspend(|| {
                    tracing::debug!(
                        "Uploaded segment {index}/{num_segments}: Size: {size}, \
                            Read: {read}, Encrypt: {encrypt}, Encode: {encode}, \
                            Upload: {upload}, Total: {total}, Overhead: {overhead:.2}% ({overhead_abs})",
                        index = segment_index + 1,
                        size = meta.bytes.human_count_bytes(),
                        read = elapsed_read.human_duration(),
                        encrypt = meta.elapsed_encrypt.human_duration(),
                        encode = meta.elapsed_encode.human_duration(),
                        upload = meta.elapsed_upload.human_duration(),
                        total = meta.elapsed_total.human_duration(),
                        overhead_abs = overhead_abs.human_count_bytes()
                    );
                });

                ctx.file_bar.inc(meta.bytes);
                if segments_remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
                    break;
                }
            }
            ctx.file_bar.finish_and_clear();
            ctx.global_ctx.bars.remove(&ctx.file_bar);
        }
    });

    let segments = RangeChunks::new(0, ctx.file().size, split_size).enumerate();
    for (index, range) in segments {
        let segment_size = (range.end - range.start) as usize;
        read_buf.resize(segment_size, 0);

        // Read the segment from the file and leave space for the tag
        let start_read = std::time::Instant::now();
        fs_file
            .read_exact(&mut read_buf)
            .await
            .with_context(|| format!("Failed to read segment {index}"))?;
        let elapsed_read = start_read.elapsed().as_secs_f64();

        {
            let mut read_times = read_times.lock().expect("lock holders do not panic");
            read_times[index] = elapsed_read;
        }

        // Send the segment to the uploader task
        let payload = uploader::Request {
            ctx: Arc::clone(&ctx),
            segment_index: index as u64,
            body: read_buf.clone(),
        };
        ctx.up_tx
            .send(payload)
            .await
            .with_context(|| format!("Failed to send segment {index} to uploader"))?;
    }

    // When the incrementer task finishes, we're done
    incrementer_task
        .await
        .expect("incrementer task does not panic");

    let file_key_b64 = util::Base64.encode(&ctx.crypto_ctx.file_key);
    let result = schema::File {
        path: ctx.file().path_rel.clone(),
        key: file_key_b64,
        last_modified: ctx.file().last_modified,
        file_size: ctx.file().size,
        segment_size: ctx.yenc_ctx.article_split_size,
    };

    ctx.file_bar.finish_and_clear();
    ctx.global_ctx.bars.remove(&ctx.file_bar);

    Ok(result)
}

pub async fn upload_dir(
    ctx: Arc<GlobalCtx>,
    yenc_ctx: Arc<YencCtx>,
    source_dir: &Path,
) -> anyhow::Result<schema::Nz2> {
    anyhow::ensure!(source_dir.is_dir(), "source_dir must be a directory");

    // Collect all files beforehand
    let source_dir_owned = source_dir.to_owned();
    let files = tokio::task::spawn_blocking(move || collect_files(source_dir_owned))
        .await
        .expect("task does not panic")?;
    let files: Arc<[File]> = files.into();

    // Ensure we have at least one file to upload
    anyhow::ensure!(!files.is_empty(), "No files found in source directory");

    let total_size = files.iter().map(|f| f.size).sum::<u64>();
    let files_bar = ctx.bars.add(util::bar_bytes(total_size));

    let (ul_in_tx, ul_in_rx) = async_channel::bounded(ctx.connections * 2);
    let (ul_out_tx, ul_out_rx) = async_channel::bounded(ctx.connections * 2);

    let mut ul_tasks = (0..ctx.connections)
        .map(|_index| {
            tokio::task::spawn(uploader::uploader_task(
                ctx.pool.clone(),
                ul_in_rx.clone(),
                ul_out_tx.clone(),
            ))
            .map(|result| result.expect("uploader tasks do not panic"))
        })
        .collect::<FuturesUnordered<_>>();

    // Drop handles we no longer need
    drop(ul_in_rx);
    drop(ul_out_tx);

    let mut result_files = Vec::<schema::File>::new();
    for (i, file) in files.iter().enumerate() {
        let start = std::time::Instant::now();
        files_bar.set_message(format!(
            "Uploading file {index}/{total}",
            index = i + 1,
            total = files.len()
        ));

        let ctx = UploadCtx::new(&ctx, &yenc_ctx, &files, i, &ul_in_tx, &ul_out_rx);
        let nz2_file = upload_file(Arc::clone(&ctx))
            .await
            .with_context(|| format!("Error uploading file {file}", file = file.path_rel))?;
        result_files.push(nz2_file);

        // Log some stats about the uploaded file
        let elapsed = start.elapsed().as_secs_f64();
        ctx.suspend(|| {
            tracing::info!(
                "Uploaded file {path}: {size} in {elapsed} ({speed})",
                path = file.path_rel,
                size = file.size.human_count_bytes(),
                elapsed = elapsed.human_duration(),
                speed = (file.size as f64 / elapsed).human_throughput_bytes(),
            );
        });
        files_bar.inc(file.size);
    }

    // Drop the remaining handles to allow the channels to close
    drop(ul_in_tx);
    drop(ul_out_rx);

    ctx.suspend(|| {
        tracing::debug!("Waiting for uploader tasks to finish");
    });

    // Wait for all uploader tasks to complete and log any errors
    let mut last_error = None;
    while let Some(result) = ul_tasks.next().await {
        if let Err(err) = result {
            ctx.suspend(|| {
                tracing::error!("Uploader task failed: {err:?}");
            });
            last_error = Some(err);
        }
    }

    files_bar.finish_and_clear();
    ctx.bars.remove(&files_bar);

    ctx.suspend(|| {
        if let Some(err) = last_error {
            tracing::error!("At least one uploader task failed!");
            tracing::error!("Last error: {err:?}");
        } else {
            tracing::info!("All files uploaded successfuly");
        }
    });

    // We're done, hooray!
    Ok(schema::Nz2 {
        nz2_version: "1.0.0".to_string(),
        encryption: schema::Encryption {
            algorithm: schema::Algorithm::ChaCha20Poly1305,
        },
        files: result_files,
    })
}

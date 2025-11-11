use std::io::SeekFrom;
use std::sync::Arc;
use std::{path::Path, time};

use anyhow::Context;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use human_repr::{HumanCount, HumanDuration, HumanThroughput};
use tokio::fs;
use tokio::io::{AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tracing::Span;

use super::context::{DownloadCtx, GlobalCtx, SuspendBars};
use super::downloader;
use crate::{schema, util};

/// Keeps pushing derived segment IDs to the `tx` channel until all segments
/// for the given file have been processed.
#[tracing::instrument(level = "debug", skip_all, fields(file))]
async fn driver_task(ctx: Arc<DownloadCtx>) -> anyhow::Result<()> {
    let file = ctx.file();
    Span::current().record("file", &file.path);

    for i in 0..ctx.num_segments() {
        let payload = downloader::Request {
            ctx: Arc::clone(&ctx),
            segment_index: i,
        };
        ctx.dl_tx
            .send(payload)
            .await
            .with_context(|| format!("Driver: Failed to forward segment {i}"))?;
    }
    Ok(())
}

/// Receives downloaded segments from the `rx` channel, decrypts them,
/// and writes them to the given output writer.
#[tracing::instrument(level = "debug", skip_all, fields(file = %ctx.file().path))]
async fn storer_task<W: AsyncWrite + AsyncSeek + Unpin>(
    ctx: Arc<DownloadCtx>,
    mut writer: W,
) -> anyhow::Result<W> {
    let mut segments_remaining = ctx.num_segments();
    while let Ok(payload) = ctx.dl_rx.recv().await {
        let downloader::Response {
            ctx,
            data,
            meta,
            segment_index,
        } = payload;
        segments_remaining -= 1;

        let Some(data) = data else {
            ctx.suspend(|| {
                tracing::warn!(
                    "Segment {segment_index} is missing for file {file}, skipping",
                    file = ctx.file().path,
                );
            });
            if segments_remaining == 0 {
                break;
            }
            continue;
        };

        let segment_range = ctx.segment_range(segment_index);
        let segment_size = segment_range.end - segment_range.start;

        let overhead = (meta.bytes_with_overhead as f64 / meta.bytes as f64 * 100.0) - 100.0;
        let overhead_abs = (meta.bytes_with_overhead - meta.bytes) as f64;

        // Write the decrypted data to the output file
        let start_write = std::time::Instant::now();
        writer
            .seek(SeekFrom::Start(segment_range.start))
            .await
            .with_context(|| {
                format!(
                    "Failed to seek for segment {index}",
                    index = payload.segment_index
                )
            })?;
        writer.write_all(&data).await.with_context(|| {
            format!(
                "Failed to write segment {index}",
                index = payload.segment_index
            )
        })?;
        let elapsed_write = start_write.elapsed().as_secs_f64();
        ctx.file_bar.inc(data.len() as u64);

        // Log some stats about the segment
        ctx.suspend(|| {
            tracing::debug!(
                "Stored segment {index}/{num_segments}: Size: {size}, \
                    Download: {download}, Decode: {decode}, Decrypt: {decrypt}, \
                    Write: {write}, Total: {total}, Overhead: {overhead:.2}% ({overhead_abs})",
                index = payload.segment_index + 1,
                num_segments = ctx.num_segments(),
                size = segment_size.human_count_bytes(),
                download = meta.elapsed_download.human_duration(),
                decode = meta.elapsed_decode.human_duration(),
                decrypt = meta.elapsed_decrypt.human_duration(),
                write = elapsed_write.human_duration(),
                total = meta.elapsed_total.human_duration(),
                overhead_abs = overhead_abs.human_count_bytes()
            );
        });

        if segments_remaining == 0 {
            break;
        }
    }

    _ = writer.flush().await;
    Ok(writer)
}

/// Reads and parses an NZ2 file from the given path.
pub async fn read_nz2(nz2_path: &Path) -> anyhow::Result<schema::Nz2> {
    let data = fs::read(nz2_path).await.with_context(|| {
        format!(
            "Failed to read NZ2 file at {path}",
            path = nz2_path.display()
        )
    })?;
    tokio::task::spawn_blocking(move || serde_json::from_slice(&data))
        .await
        .expect("task does not panic")
        .with_context(|| {
            format!(
                "Failed to parse NZ2 file at {path} as JSON",
                path = nz2_path.display()
            )
        })
}

/// Downloads a single file described by the given NZ2 file schema,
/// writing it to the specified output directory.
#[tracing::instrument(level = "debug", skip_all, fields(file))]
pub async fn download_file(
    ctx: Arc<DownloadCtx>,
    file_index: usize,
    output_dir: &Path,
) -> anyhow::Result<()> {
    let file = &ctx.files[file_index];
    Span::current().record("file", &file.path);

    // TODO: Verify that the output file is within the output directory
    //       to prevent directory traversal attacks
    let output_file_path = output_dir.join(&file.path);

    // Get the path to the folder containing the output file
    let output_dir_path = output_file_path.parent().with_context(|| {
        format!(
            "Output directory parent of {output} does not exist",
            output = output_file_path.display(),
        )
    })?;

    // Create the directory for the output file
    fs::create_dir_all(output_dir_path).await.with_context(|| {
        format!(
            "Failed to create output directory {dir}",
            dir = output_dir_path.display(),
        )
    })?;

    // Create the output file we write the splits to
    // Don't use a buffered writer since we write ~1MB segments
    let output_file = fs::File::options()
        .write(true)
        .create_new(true)
        .open(&output_file_path)
        .await
        .with_context(|| {
            format!(
                "Failed to create output file {output}",
                output = output_file_path.display(),
            )
        })?;

    // Try to preallocate space for the output file
    if let Err(err) = output_file.set_len(file.file_size).await {
        ctx.suspend(|| {
            tracing::warn!(
                "Failed to preallocate space for file {}: {err:?}",
                file.path,
            );
        });
    };

    // Stores downloaded segments to the output file
    let storer_task = tokio::task::spawn(storer_task(Arc::clone(&ctx), output_file));

    // Derives segment IDs and sends them to the downloader tasks
    let driver_task = tokio::task::spawn(driver_task(Arc::clone(&ctx)));

    // Wait for the deriver and storer tasks to complete
    driver_task
        .await
        .expect("task does not panic")
        .context("Deriver task failed")?;
    let output = storer_task
        .await
        .expect("task does not panic")
        .context("Storer task failed")?;

    // Attempt to set the last modified time if it was provided
    if let Some(timestamp) = ctx.file().last_modified
        && let Err(err) = util::set_last_modified_from_unix_timestamp(output, timestamp).await
    {
        ctx.suspend(|| {
            tracing::warn!(
                "Failed to set last modified time for file {}: {err:?}",
                ctx.file().path
            );
        });
    }

    ctx.file_bar.finish_and_clear();
    ctx.global_ctx.bars.remove(&ctx.file_bar);

    Ok(())
}

pub async fn download_nz2(
    ctx: Arc<GlobalCtx>,
    nz2_path: &Path,
    output_dir: &Path,
) -> anyhow::Result<()> {
    anyhow::ensure!(output_dir.is_dir(), "output_dir must be a directory");
    anyhow::ensure!(nz2_path.is_file(), "nz2_path must be a file");

    // Read and parse the NZ2 file
    let nz2 = read_nz2(nz2_path).await?;
    let files: Arc<[schema::File]> = nz2.files.into();

    let total_size = files.iter().map(|f| f.file_size).sum::<u64>();
    let files_bar = ctx.bars.add(util::bar_bytes(total_size));

    let (dl_in_tx, dl_in_rx) = async_channel::bounded(ctx.connections * 2);
    let (dl_out_tx, dl_out_rx) = async_channel::bounded(ctx.connections * 2);

    let mut dl_tasks = (0..ctx.connections)
        .map(|_index| {
            tokio::task::spawn(downloader::downloader_task(
                ctx.pool.clone(),
                dl_in_rx.clone(),
                dl_out_tx.clone(),
            ))
            .map(|result| result.expect("downloader tasks do not panic"))
        })
        .collect::<FuturesUnordered<_>>();

    // Drop handles we no longer need
    drop(dl_in_rx);
    drop(dl_out_tx);

    // Download each file in the NZ2 file
    for (i, file) in files.iter().enumerate() {
        let start = time::Instant::now();
        files_bar.set_message(format!(
            "Downloading file {index}/{total}",
            index = i + 1,
            total = files.len()
        ));

        let ctx = DownloadCtx::new(&ctx, &files, i, &dl_in_tx, &dl_out_rx)?;
        download_file(Arc::clone(&ctx), i, output_dir)
            .await
            .with_context(|| {
                format!(
                    "Error downloading file {file} of NZ2 file {nz2}",
                    file = file.path,
                    nz2 = nz2_path.display()
                )
            })?;

        // Log some stats about the downloaded file
        let elapsed = start.elapsed().as_secs_f64();
        ctx.suspend(|| {
            tracing::info!(
                "Downloaded file {path}: {size} in {elapsed} ({speed})",
                path = file.path,
                size = file.file_size.human_count_bytes(),
                elapsed = elapsed.human_duration(),
                speed = (file.file_size as f64 / elapsed).human_throughput_bytes(),
            );
        });
        files_bar.inc(file.file_size);
    }

    // Drop the remaining handles to allow the channels to close
    drop(dl_in_tx);
    drop(dl_out_rx);

    // Wait for all downloader tasks to complete and log any errors
    let mut last_error = None;
    while let Some(result) = dl_tasks.next().await {
        if let Err(err) = result {
            ctx.suspend(|| {
                tracing::error!("Downloader task failed: {err:?}");
            });
            last_error = Some(err);
        }
    }

    files_bar.finish_and_clear();
    ctx.bars.remove(&files_bar);

    ctx.suspend(|| {
        tracing::info!("All files uploaded successfuly");
    });

    Ok(())
}

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use nz2_poc_rs::{bar, nz2, util};
use tokio::{fs, io::AsyncWriteExt};

const DEFAULT_LINE_WIDTH: u32 = 128;
const DEFAULT_SPLIT_SIZE: u64 = 1024 * 1024; // 1 MiB
const DEFAULT_CONNECTIONS: usize = 10;
const DEFAULT_GROUP: &[&str] = &["alt.test"];

/// A proof-of-concept implementation of the NZB-encryption-spec
#[derive(Parser)]
#[command(version, about, long_about)]
enum Args {
    /// Upload a directory to NZ2 store
    Upload {
        /// Input directory with the files to upload
        #[arg(long)]
        input_dir: std::path::PathBuf,
        /// Output NZ2 file path
        #[arg(long)]
        output_file: std::path::PathBuf,
        /// Line width for YEnc encoding
        #[arg(long, default_value_t = DEFAULT_LINE_WIDTH)]
        line_width: u32,
        /// Split size for splitting files into parts (in bytes)
        #[arg(long, default_value_t = DEFAULT_SPLIT_SIZE)]
        split_size: u64,
        /// News server address
        #[arg(long)]
        news_server: String,
        /// News server username
        #[arg(long)]
        news_username: String,
        /// News server password
        #[arg(long)]
        news_password: String,
        #[arg(long, default_value_t = DEFAULT_CONNECTIONS)]
        connections: usize,
        #[arg(long)]
        group: Vec<String>,
        #[arg(long, default_value_t = false)]
        no_progress: bool,
    },
    /// Download an NZ2 file from NZ2 store
    Download {
        /// Input NZ2 file path
        #[arg(long)]
        input_file: std::path::PathBuf,
        /// Output directory to write downloaded files
        #[arg(long)]
        output_dir: std::path::PathBuf,
        /// News server address
        #[arg(long)]
        news_server: String,
        /// News server username
        #[arg(long)]
        news_username: String,
        /// News server password
        #[arg(long)]
        news_password: String,
        #[arg(long, default_value_t = DEFAULT_CONNECTIONS)]
        connections: usize,
        #[arg(long, default_value_t = false)]
        no_progress: bool,
    },
}

#[tracing::instrument(level = "trace", skip_all)]
async fn prepare_pool(
    pool: &nntp_rs::Pool,
    connections: usize,
    bars: &bar::MultiProgress,
) -> anyhow::Result<()> {
    tracing::info!("Preparing {connections} NNTP pool connections");

    let bar = bars.add(util::bar_items(connections as u64));
    bar.set_message("Preparing Connections".to_string());

    let mut buffer = Vec::with_capacity(connections);
    for i in 0..connections {
        let mut conn = pool.get().await.with_context(|| {
            format!(
                "Failed to get connection {index}/{connections}",
                index = i + 1
            )
        })?;
        _ = conn.date().await.with_context(|| {
            format!(
                "Failed to validate connection {index}/{connections}",
                index = i + 1
            )
        })?;
        buffer.push(conn);
        bar.inc(1);
    }
    drop(buffer);

    bar.finish_and_clear();
    bars.remove(&bar);

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    util::init_tracing();
    let args = Args::parse();

    match args {
        Args::Upload {
            input_dir,
            output_file,
            line_width,
            split_size,
            news_server: host,
            news_username: username,
            news_password: password,
            connections,
            group,
            no_progress,
        } => {
            let bars = bar::MultiProgress::new(no_progress);

            let manager = nntp_rs::Manager::with_credentials(host, username, Some(password));
            let pool = nntp_rs::Pool::builder(manager)
                .max_size(connections)
                .build()?;

            // Create the output file now to avoid uploading and then failing to write the NZ2 file
            let mut output_file = fs::File::options()
                .write(true)
                .create_new(true)
                .open(&output_file)
                .await
                .with_context(|| {
                    format!(
                        "Failed to create output NZ2 file at {}",
                        output_file.display()
                    )
                })?;

            let newsgroups = if group.is_empty() {
                DEFAULT_GROUP.iter().map(|s| s.to_string()).collect()
            } else {
                group
            };

            prepare_pool(&pool, connections, &bars).await?;

            let ctx = Arc::new(nz2::context::GlobalCtx {
                pool: pool.clone(),
                connections,
                bars,
            });
            let yenc_ctx = Arc::new(nz2::context::YencCtx {
                yenc_line_width: line_width,
                article_split_size: split_size,
                newsgroups: newsgroups.clone(),
            });

            // Perform the upload
            let nz2 = nz2_poc_rs::nz2::upload_dir(ctx, yenc_ctx, &input_dir).await?;

            // Serialize to JSON
            let nz2_json = tokio::task::spawn_blocking(move || serde_json::to_vec_pretty(&nz2))
                .await
                .expect("task does not panic")?;

            // Write to output file
            output_file.write_all(&nz2_json).await?;
        }
        Args::Download {
            input_file,
            output_dir,
            news_server: host,
            news_username: username,
            news_password: password,
            connections,
            no_progress,
        } => {
            let bars = bar::MultiProgress::new(no_progress);

            let manager = nntp_rs::Manager::with_credentials(host, username, Some(password));
            let pool = nntp_rs::Pool::builder(manager)
                .max_size(connections)
                .build()?;
            prepare_pool(&pool, connections, &bars).await?;

            let ctx = Arc::new(nz2::context::GlobalCtx {
                pool: pool.clone(),
                connections,
                bars,
            });

            nz2_poc_rs::nz2::download_nz2(ctx, &input_file, &output_dir).await?;
        }
    }

    Ok(())
}

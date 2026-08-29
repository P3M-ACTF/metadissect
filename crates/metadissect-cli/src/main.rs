mod api;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use metadissect::export::{to_csv, to_json, to_markdown};
use metadissect::{analyze_html_string, analyze_json_string, analyze_path, AnalyzeOptions};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "metadissect",
    version,
    about = "Exhaustive local metadata analysis (library + CLI + JSON API, no web UI)."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// File to analyze (when not using a subcommand)
    path: Option<PathBuf>,
    #[arg(long, short = 'f', default_value = "table")]
    format: OutputFormat,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a local file
    Analyze {
        path: PathBuf,
        #[arg(long, short = 'f', default_value = "table")]
        format: OutputFormat,
    },
    /// Analyze a pasted HTML document
    Html {
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "table")]
        format: OutputFormat,
    },
    /// Analyze a pasted JSON document
    Json {
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, short = 'f', default_value = "table")]
        format: OutputFormat,
    },
    /// Fetch a public URL (SSRF-safe) and analyze it
    Fetch {
        url: String,
        #[arg(long, short = 'f', default_value = "table")]
        format: OutputFormat,
    },
    /// JSON HTTP API only (no web UI). Requires `--api`.
    Serve {
        /// Enable the JSON API (MetaDissect has no educational UI)
        #[arg(long)]
        api: bool,
        /// Bind address (default localhost; warn if 0.0.0.0)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Listen port
        #[arg(long, default_value = "8787")]
        port: u16,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Markdown,
    Csv,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Analyze { path, format }) => print_analysis_path(&path, format)?,
        Some(Command::Html { file, format }) => {
            let name = file
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
                .or_else(|| Some("stdin.html".into()));
            let html = read_or_stdin(file)?;
            let a = analyze_html_string(&html, name);
            print_analysis(&a, format)?;
        }
        Some(Command::Json { file, format }) => {
            let name = file
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
                .or_else(|| Some("stdin.json".into()));
            let json = read_or_stdin(file)?;
            let a = analyze_json_string(&json, name);
            print_analysis(&a, format)?;
        }
        Some(Command::Fetch { url, format }) => {
            let a = metadissect::fetch::fetch_and_analyze(&url).await?;
            print_analysis(&a, format)?;
        }
        Some(Command::Serve {
            api: enable_api,
            host,
            port,
        }) => {
            if !enable_api {
                anyhow::bail!(
                    "MetaDissect has no web UI. Pass --api to serve the JSON HTTP API, e.g.:\n  metadissect serve --api\n  metadissect serve --api --host 127.0.0.1 --port 8787"
                );
            }
            api::serve(&host, port).await?;
        }
        None => {
            let path = cli.path.ok_or_else(|| {
                anyhow::anyhow!(
                    "pass a file path or a subcommand (analyze, fetch, html, json, serve)"
                )
            })?;
            print_analysis_path(&path, cli.format)?;
        }
    }
    Ok(())
}

fn print_analysis_path(path: &Path, format: OutputFormat) -> Result<()> {
    let a = analyze_path(path)?;
    print_analysis(&a, format)
}

fn print_analysis(a: &metadissect::Analysis, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", to_json(a)?),
        OutputFormat::Csv => print!("{}", to_csv(a)),
        OutputFormat::Markdown => print!("{}", to_markdown(a)),
        OutputFormat::Table => print_table(a),
    }
    Ok(())
}

fn print_table(a: &metadissect::Analysis) {
    println!(
        "MetaDissect  {}  {}  {} bytes  entropy={:.3}",
        a.filename.as_deref().unwrap_or("-"),
        a.mime,
        a.size,
        a.entropy
    );
    println!("SHA-256 {}  MD5 {}", a.hashes.sha256, a.hashes.md5);
    println!();
    for sec in &a.sections {
        println!("── {} ──", sec.label);
        for f in &sec.fields {
            let ns = f.namespace.as_deref().unwrap_or("");
            let val = metadissect::truncate_chars(&f.value, 120);
            if ns.is_empty() {
                println!("  {:28} {}", f.key, val);
            } else {
                println!("  {:28} {}  [{}]", f.key, val, ns);
            }
        }
        println!();
    }
    if !a.warnings.is_empty() {
        println!("── Warnings ──");
        for w in &a.warnings {
            println!("  ! {w}");
        }
    }
    let _ = AnalyzeOptions::default();
}

fn read_or_stdin(file: Option<PathBuf>) -> Result<String> {
    if let Some(p) = file {
        Ok(std::fs::read_to_string(p)?)
    } else {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    }
}

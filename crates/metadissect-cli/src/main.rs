mod api;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use metadissect::export::{to_csv, to_json, to_markdown};
use metadissect::{
    analyze_html_string, analyze_json_string, analyze_path_with_options, AnalyzeOptions,
};
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
    #[arg(long, short = 'f', default_value = "table", global = true)]
    format: OutputFormat,
    /// Full PNG chunk list and longer field values
    #[arg(short = 'v', long, global = true)]
    verbose: bool,
    /// Only show these section ids (comma-separated), e.g. c2pa,normalized,general
    #[arg(long, value_delimiter = ',', global = true)]
    sections: Option<Vec<String>>,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a local file
    Analyze { path: PathBuf },
    /// Analyze a pasted HTML document
    Html {
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Analyze a pasted JSON document
    Json {
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Fetch a public URL (SSRF-safe) and analyze it
    Fetch { url: String },
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

struct DisplayOpts {
    format: OutputFormat,
    verbose: bool,
    sections: Option<Vec<String>>,
}

impl DisplayOpts {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            format: cli.format,
            verbose: cli.verbose,
            sections: cli.sections.clone(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let display = DisplayOpts::from_cli(&cli);
    match cli.command {
        Some(Command::Analyze { path }) => print_analysis_path(&path, &display)?,
        Some(Command::Html { file }) => {
            let name = file
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
                .or_else(|| Some("stdin.html".into()));
            let html = read_or_stdin(file)?;
            let a = analyze_html_string(&html, name);
            print_analysis(&a, &display)?;
        }
        Some(Command::Json { file }) => {
            let name = file
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
                .or_else(|| Some("stdin.json".into()));
            let json = read_or_stdin(file)?;
            let a = analyze_json_string(&json, name);
            print_analysis(&a, &display)?;
        }
        Some(Command::Fetch { url }) => {
            let a = metadissect::fetch::fetch_and_analyze_with(
                &url,
                AnalyzeOptions::default().with_verbose(display.verbose),
            )
            .await?;
            print_analysis(&a, &display)?;
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
            print_analysis_path(&path, &display)?;
        }
    }
    Ok(())
}

fn print_analysis_path(path: &Path, display: &DisplayOpts) -> Result<()> {
    let a = analyze_path_with_options(
        path,
        AnalyzeOptions::default().with_verbose(display.verbose),
    )?;
    print_analysis(&a, display)
}

fn print_analysis(a: &metadissect::Analysis, display: &DisplayOpts) -> Result<()> {
    let filtered = filter_analysis(a, display.sections.as_deref())?;
    match display.format {
        OutputFormat::Json => println!("{}", to_json(&filtered)?),
        OutputFormat::Csv => print!("{}", to_csv(&filtered)),
        OutputFormat::Markdown => print!("{}", to_markdown(&filtered)),
        OutputFormat::Table => print_table(&filtered, display.verbose),
    }
    Ok(())
}

fn filter_analysis(
    a: &metadissect::Analysis,
    sections: Option<&[String]>,
) -> Result<metadissect::Analysis> {
    let mut out = a.clone();
    if let Some(filter) = sections {
        if !filter.is_empty() {
            out.sections
                .retain(|s| section_matches(&s.id, filter));
        }
    }
    Ok(out)
}

fn section_matches(id: &str, filter: &[String]) -> bool {
    filter.iter().any(|want| {
        let want = want.trim();
        if want.is_empty() {
            return false;
        }
        id.eq_ignore_ascii_case(want)
            || id
                .to_ascii_lowercase()
                .starts_with(&format!("{}-", want.to_ascii_lowercase()))
    })
}

fn print_table(a: &metadissect::Analysis, verbose: bool) {
    println!(
        "MetaDissect  {}  {}  {} bytes  entropy={:.3}",
        a.filename.as_deref().unwrap_or("-"),
        a.mime,
        a.size,
        a.entropy
    );
    println!("SHA-256 {}  MD5 {}", a.hashes.sha256, a.hashes.md5);
    println!();
    let max_chars = if verbose { 2000 } else { 120 };
    for sec in &a.sections {
        println!("── {} ──", sec.label);
        for f in &sec.fields {
            let ns = f.namespace.as_deref().unwrap_or("");
            let val = metadissect::truncate_chars(&f.value, max_chars);
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

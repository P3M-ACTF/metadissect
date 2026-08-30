use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline};
use ratatui::Frame;

use crate::stats::ServeStats;

pub struct ServeDashboardOptions {
    pub title: String,
    pub url: String,
}

pub fn run_serve_dashboard(
    stats: Arc<ServeStats>,
    stop: Arc<AtomicBool>,
    opts: ServeDashboardOptions,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let result = loop {
        if stop.load(Ordering::Relaxed) {
            break Ok(());
        }
        terminal.draw(|f| draw_dashboard(f, &stats, &opts))?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        stop.store(true, Ordering::Relaxed);
                        break Ok(());
                    }
                    _ => {}
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    stop.store(true, Ordering::Relaxed);
                    break Ok(());
                }
            }
        }
    };

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn draw_dashboard(f: &mut Frame, stats: &ServeStats, opts: &ServeDashboardOptions) {
    let snap = stats.snapshot();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(f.area());

    let title = Paragraph::new(format!("{}  {}", opts.title, opts.url))
        .block(Block::default().borders(Borders::ALL).title("Serve"));
    f.render_widget(title, chunks[0]);

    let stats_line = format!(
        "RPS {:.1}  total {}  2xx {}  4xx {}  5xx {}  p50 {}ms  p99 {}ms",
        snap.rps,
        snap.total,
        snap.ok_2xx,
        snap.err_4xx,
        snap.err_5xx,
        snap.p50_ms,
        snap.p99_ms
    );
    let stats_p = Paragraph::new(stats_line)
        .block(Block::default().borders(Borders::ALL).title("Stats"));
    f.render_widget(stats_p, chunks[1]);

    let spark_data: Vec<u64> = snap.sparkline.clone();
    let max = spark_data.iter().copied().max().unwrap_or(1).max(1);
    let spark = Sparkline::default()
        .data(
            spark_data
                .iter()
                .map(|v| ((*v as f64 / max as f64) * 100.0) as u64)
                .collect::<Vec<_>>(),
        )
        .style(Style::default().fg(Color::Cyan));
    let spark_block = spark.block(Block::default().borders(Borders::ALL).title("RPS sparkline"));
    f.render_widget(spark_block, chunks[2]);

    let last = format!(
        "Last: {} → {}    q or Ctrl+C to stop",
        snap.last_route,
        snap.last_status
    );
    let foot = Paragraph::new(Line::from(last)).style(Style::default().fg(Color::DarkGray));
    f.render_widget(foot, chunks[3]);
}

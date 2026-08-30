use std::io;
use std::path::Path;

use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

/// Confirm writing a mutated copy when TUI is active. Returns `false` if the user declines.
pub fn confirm_mutate_write(input: &Path, output: &Path, action: &str) -> io::Result<bool> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;
    let mut confirmed = false;
    let result: io::Result<()> = loop {
        terminal.draw(|f| draw_confirm(f, input, output, action))?;
        if event::poll(std::time::Duration::from_millis(120))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                        confirmed = true;
                        break Ok(());
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Char('q') => {
                        break Ok(());
                    }
                    _ => {}
                }
            }
        }
    };
    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result?;
    Ok(confirmed)
}

fn draw_confirm(f: &mut Frame, input: &Path, output: &Path, action: &str) {
    let area = centered_rect(70, 40, f.area());
    let block = Block::default()
        .borders(Borders::ALL)
        .title("MetaFake — confirm write")
        .style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let text = format!(
        "Action: {action}\n\nInput (read-only):\n  {}\n\nOutput copy (-o required):\n  {}\n\nThis alters evidence on the COPY only.\nNever overwrites the original.\n\n[y] write copy   [n/q/Esc] cancel",
        input.display(),
        output.display()
    );
    let para = Paragraph::new(text)
        .wrap(Wrap { trim: true })
        .style(Style::default().add_modifier(Modifier::BOLD));
    f.render_widget(para, inner);
}

fn centered_rect(pct_x: u16, pct_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

use std::io;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use metadissect::{Analysis, Section};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

/// Use interactive TUI when stdout is a TTY, format is not structured export, and --no-tui was not passed.
pub fn should_use_analyze_tui(structured_format: bool, no_tui: bool) -> bool {
    !no_tui && !structured_format && crate::net::is_tty_stdio()
}

pub fn run_analyze_tui(analysis: &Analysis) -> io::Result<()> {
    let mut app = AnalyzeApp::new(analysis);
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;
    let result = loop {
        terminal.draw(|f| draw_analyze(f, &mut app))?;
        if event::poll(std::time::Duration::from_millis(120))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                    KeyCode::Char('j') | KeyCode::Down => app.next_field(),
                    KeyCode::Char('k') | KeyCode::Up => app.prev_field(),
                    KeyCode::PageDown if !app.search_mode => app.page_down_fields(),
                    KeyCode::PageUp if !app.search_mode => app.page_up_fields(),
                    KeyCode::Home if !app.search_mode => app.first_field(),
                    KeyCode::End if !app.search_mode => app.last_field(),
                    KeyCode::Char('/') => app.search_mode = true,
                    KeyCode::Char('c') => app.copy_selection(),
                    KeyCode::Char('?') => app.show_help = !app.show_help,
                    KeyCode::Char(c) if app.search_mode => {
                        if c == '\n' {
                            app.search_mode = false;
                        } else if c == '\x08' || c == '\x7f' {
                            app.search_query.pop();
                        } else {
                            app.search_query.push(c);
                            app.sync_selection();
                        }
                    }
                    KeyCode::Backspace if app.search_mode => {
                        app.search_query.pop();
                        app.sync_selection();
                    }
                    KeyCode::Enter if app.search_mode => app.search_mode = false,
                    _ => {}
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
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

struct FlatField {
    section_label: String,
    key: String,
    value: String,
    namespace: String,
}

struct AnalyzeApp {
    sections: Vec<Section>,
    flat: Vec<FlatField>,
    filtered: Vec<usize>,
    section_sel: usize,
    field_sel: usize,
    section_list_state: ListState,
    field_list_state: ListState,
    field_visible: usize,
    search_mode: bool,
    search_query: String,
    show_help: bool,
    title: String,
    warnings: Vec<String>,
}

impl AnalyzeApp {
    fn new(analysis: &Analysis) -> Self {
        let flat = flatten(analysis);
        let mut app = Self {
            sections: analysis.sections.clone(),
            flat,
            filtered: Vec::new(),
            section_sel: 0,
            field_sel: 0,
            section_list_state: ListState::default(),
            field_list_state: ListState::default(),
            field_visible: 1,
            search_mode: false,
            search_query: String::new(),
            show_help: false,
            title: format!(
                "{}  {}  {} bytes",
                analysis.filename.as_deref().unwrap_or("-"),
                analysis.mime,
                analysis.size
            ),
            warnings: analysis.warnings.clone(),
        };
        app.sync_selection();
        app
    }

    fn sync_selection(&mut self) {
        let q = app_query(&self.search_query);
        self.filtered.clear();
        for (i, f) in self.flat.iter().enumerate() {
            if q.is_empty()
                || f.key.to_ascii_lowercase().contains(&q)
                || f.value.to_ascii_lowercase().contains(&q)
                || f.namespace.to_ascii_lowercase().contains(&q)
            {
                self.filtered.push(i);
            }
        }
        if self.section_sel >= self.sections.len() {
            self.section_sel = 0;
        }
        if self.field_sel >= self.filtered.len() {
            self.field_sel = 0;
        }
    }

    fn next_field(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        self.field_sel = (self.field_sel + 1) % self.filtered.len();
        self.align_section();
    }

    fn prev_field(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        self.field_sel = if self.field_sel == 0 {
            self.filtered.len() - 1
        } else {
            self.field_sel - 1
        };
        self.align_section();
    }

    fn page_down_fields(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let step = self.field_visible.max(1);
        self.field_sel = (self.field_sel + step).min(self.filtered.len() - 1);
        self.align_section();
    }

    fn page_up_fields(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let step = self.field_visible.max(1);
        self.field_sel = self.field_sel.saturating_sub(step);
        self.align_section();
    }

    fn first_field(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        self.field_sel = 0;
        self.align_section();
    }

    fn last_field(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        self.field_sel = self.filtered.len() - 1;
        self.align_section();
    }

    fn align_section(&mut self) {
        if let Some(&idx) = self.filtered.get(self.field_sel) {
            let label = &self.flat[idx].section_label;
            if let Some(si) = self.sections.iter().position(|s| s.label == *label) {
                self.section_sel = si;
            }
        }
    }

    fn copy_selection(&mut self) {
        if let Some(&idx) = self.filtered.get(self.field_sel) {
            let f = &self.flat[idx];
            let text = format!("{}={}", f.key, f.value);
            let _ = io::stdout().write_all(text.as_bytes());
        }
    }
}

fn app_query(q: &str) -> String {
    q.trim().to_ascii_lowercase()
}

fn flatten(analysis: &Analysis) -> Vec<FlatField> {
    let mut out = Vec::new();
    for sec in &analysis.sections {
        for f in &sec.fields {
            out.push(FlatField {
                section_label: sec.label.clone(),
                key: f.key.clone(),
                value: f.value.clone(),
                namespace: f.namespace.clone().unwrap_or_default(),
            });
        }
    }
    out
}

fn draw_analyze(f: &mut Frame, app: &mut AnalyzeApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(3),
        ])
        .split(f.area());

    let header = Paragraph::new(app.title.clone())
        .block(Block::default().borders(Borders::ALL).title("Analyze"));
    f.render_widget(header, chunks[0]);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(42),
            Constraint::Percentage(30),
        ])
        .split(chunks[1]);

    let highlight = Style::default().add_modifier(Modifier::REVERSED);

    let section_items: Vec<ListItem> = app
        .sections
        .iter()
        .map(|s| ListItem::new(format!("{} ({})", s.label, s.fields.len())))
        .collect();
    let sections = List::new(section_items)
        .block(Block::default().borders(Borders::ALL).title("Sections"))
        .highlight_style(highlight);
    app.section_list_state.select(Some(app.section_sel));
    f.render_stateful_widget(sections, mid[0], &mut app.section_list_state);

    app.field_visible = list_visible_items(mid[1].height);
    let field_items: Vec<ListItem> = app
        .filtered
        .iter()
        .map(|&fi| {
            let f = &app.flat[fi];
            ListItem::new(format!("{}  {}", f.key, truncate(&f.value, 48)))
        })
        .collect();
    let fields = List::new(field_items)
        .block(Block::default().borders(Borders::ALL).title("Fields"))
        .highlight_style(highlight);
    app.field_list_state.select(Some(app.field_sel));
    f.render_stateful_widget(fields, mid[1], &mut app.field_list_state);

    let warn_text = if app.warnings.is_empty() {
        "No warnings".to_string()
    } else {
        app.warnings.join("\n")
    };
    let warnings = Paragraph::new(warn_text)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Warnings"));
    f.render_widget(warnings, mid[2]);

    let field_counter = if app.filtered.is_empty() {
        String::new()
    } else {
        format!(
            " · {}/{}",
            app.field_sel + 1,
            app.filtered.len()
        )
    };
    let footer = if app.show_help {
        format!(
            "j/k move · PgUp/PgDn · / filter · c copy · q quit · ? help{field_counter}"
        )
    } else if app.search_mode {
        format!("Filter: {}_{field_counter}", app.search_query)
    } else {
        format!("j/k fields · / search · c copy · q quit · ? help{field_counter}")
    };
    let foot = Paragraph::new(footer).style(Style::default().fg(Color::DarkGray));
    f.render_widget(foot, chunks[2]);

    if app.search_mode {
        let area = centered_rect(60, 20, f.area());
        let panel = Paragraph::new(format!("Filter: {}", app.search_query))
            .block(Block::default().borders(Borders::ALL).title("Search"));
        f.render_widget(panel, area);
    }
}

fn list_visible_items(height: u16) -> usize {
    height.saturating_sub(2).max(1) as usize
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
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

use std::io::Write;

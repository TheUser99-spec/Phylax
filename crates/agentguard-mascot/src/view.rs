//! DogView — renders the dog sprite in the terminal using ratatui.
//!
//! Handles the render loop:
//! - Advances the sprite animation every ~120ms
//! - Draws the current frame centered in the terminal
//! - Shows animation name and last event as a footer
//!
//! Completely independent of the controller — only needs the DogSprite.

use crate::sprite::DogSprite;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm::ExecutableCommand;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use std::io;
use std::time::Duration;

/// The frame refresh interval in milliseconds.
const TICK_MS: u64 = 120;

pub struct DogView {
    /// Owns the sprite and its animations.
    sprite: DogSprite,
    /// Whether the view is running.
    running: bool,
    /// Last event label (set externally, displayed in footer).
    event_label: Option<String>,
    /// Animation name label (displayed in footer).
    anim_label: String,
}

impl DogView {
    /// Create a new DogView with the given sprite.
    pub fn new(sprite: DogSprite) -> Self {
        Self {
            sprite,
            running: true,
            event_label: None,
            anim_label: "idle".to_string(),
        }
    }

    /// Stop the render loop.
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Set the event label shown in the footer.
    pub fn set_event(&mut self, event: &str) {
        self.event_label = Some(event.to_string());
    }

    /// Set the animation label shown in the footer.
    pub fn set_animation_label(&mut self, label: &str) {
        self.anim_label = label.to_string();
    }

    /// Run the main render loop.
    ///
    /// Each tick:
    /// 1. Advance the sprite animation
    /// 2. Draw the current frame
    /// 3. Handle keyboard (only 'q' quits)
    /// 4. Sleep for TICK_MS
    pub fn run(mut self) -> io::Result<()> {
        enable_raw_mode()?;
        io::stdout().execute(crossterm::terminal::EnterAlternateScreen)?;

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(io::stdout()))?;

        while self.running {
            // Advance animation
            self.sprite.next_frame();

            // Draw
            terminal.draw(|f| self.draw(f))?;

            // Handle quit key only (non-blocking)
            if crossterm::event::poll(Duration::from_millis(1)).unwrap_or(false) {
                if let Ok(crossterm::event::Event::Key(key)) = crossterm::event::read() {
                    if key.code == crossterm::event::KeyCode::Char('q')
                        || key.code == crossterm::event::KeyCode::Esc
                    {
                        self.running = false;
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(TICK_MS));
        }

        disable_raw_mode()?;
        io::stdout().execute(crossterm::terminal::LeaveAlternateScreen)?;
        Ok(())
    }

    /// Draw a single frame.
    fn draw(&self, f: &mut Frame) {
        let area = f.area();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(3)])
            .split(area);

        // Center the sprite
        let frame_str = self.sprite.current_frame();
        let lines: Vec<Line> = frame_str
            .lines()
            .map(|l| {
                Line::from(Span::styled(
                    l.to_string(),
                    Style::default().fg(Color::Cyan),
                ))
            })
            .collect();

        let sprite_block = Block::default()
            .borders(Borders::ALL)
            .title(" Guardian Husky ")
            .title_alignment(Alignment::Center)
            .border_style(Style::default().fg(Color::Cyan));

        let p = Paragraph::new(Text::from(lines))
            .block(sprite_block)
            .alignment(Alignment::Center);
        f.render_widget(p, chunks[0]);

        // Footer with animation + event info
        let event_text = self.event_label.as_deref().unwrap_or("none");
        let footer_line = Line::from(vec![
            Span::styled(
                format!(" animation: {} ", self.anim_label),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" | "),
            Span::styled(" event: ", Style::default().fg(Color::Gray)),
            Span::styled(event_text, Style::default().fg(Color::Green)),
            Span::raw(" | "),
            Span::styled(
                " q/esc ",
                Style::default().bg(Color::DarkGray).fg(Color::White),
            ),
            Span::raw(" quit"),
        ]);

        let footer = Paragraph::new(footer_line).block(Block::default().borders(Borders::TOP));
        f.render_widget(footer, chunks[1]);
    }
}

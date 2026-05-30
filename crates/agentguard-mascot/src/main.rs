//! App — wires DogSprite, DogController, and DogView together.
//!
//! Exposes the public entry point:
//! - App::new() — creates all components
//! - App::trigger_event(&mut self, event: &str) — called by SBS
//! - App::run(self) — starts the render loop

mod controller;
mod sprite;
mod sprites;
mod view;

use controller::DogController;
use sprite::DogSprite;
use view::DogView;

/// Main application struct.
///
/// Wires together the three architectural layers:
/// - DogSprite — pixel art + animations
/// - DogController — maps SBS events to animations
/// - DogView — terminal rendering (ratatui)
pub struct App {
    sprite: DogSprite,
    controller: DogController,
    view: Option<DogView>,
}

impl App {
    /// Create a new App with all components initialized.
    /// The dog starts in the "idle" animation.
    pub fn new() -> Self {
        Self {
            sprite: DogSprite::new(),
            controller: DogController::new(),
            view: None,
        }
    }

    /// Called by the external SBS (Sentinel Behavior System) to trigger
    /// a behavior change in the mascot.
    ///
    /// Example events:
    /// - "agent_detected" → surprised
    /// - "blocked" → sad
    /// - "all_clear" → happy
    /// - "scanning" → walk
    /// - "startup" → idle
    ///
    /// If the view is running, updates the display immediately.
    /// Returns the animation name that was selected.
    pub fn trigger_event(&mut self, event: &str) -> &str {
        let anim = self.controller.trigger_event(event);
        self.sprite.set_animation(anim);

        if let Some(ref mut view) = self.view {
            view.set_event(event);
            view.set_animation_label(anim);
        }

        anim
    }

    /// Start the terminal render loop. Blocks until the user presses 'q'.
    ///
    /// Takes ownership of the sprite and view. The view runs independently
    /// with its own timer. Call `trigger_event()` before `run()` to set
    /// the initial animation.
    pub fn run(mut self) -> std::io::Result<()> {
        let view = DogView::new(std::mem::take(&mut self.sprite));
        self.view = Some(view);

        // Use a separate thread to allow external event injection.
        // In production, the SBS would call trigger_event() from another thread.
        // For demo purposes, the view runs the main loop.
        let mut view = self.view.take().unwrap();
        view.run()
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

// ── Binary entry point ────────────────────────────────────────────────────

fn main() -> std::io::Result<()> {
    let mut app = App::new();

    // Example: start with idle, then the SBS would call trigger_event()
    app.trigger_event("startup");

    // In a real SBS integration, a background thread would call:
    //   app.trigger_event("agent_detected");
    //   app.trigger_event("blocked");
    //   app.trigger_event("all_clear");
    // based on security events.

    app.run()
}

// ── Integration with SBS ──────────────────────────────────────────────────
//
// To integrate with the AgentGuard daemon, spawn the mascot in a separate
// thread and share an Arc<Mutex<App>> or use a channel pattern:
//
// ```rust,ignore
// use std::sync::{Arc, Mutex};
// use std::thread;
//
// let app = Arc::new(Mutex::new(agentguard_mascot::App::new()));
// let app_clone = Arc::clone(&app);
//
// // Spawn the mascot UI thread
// let ui_thread = thread::spawn(move || {
//     let app = app_clone.lock().unwrap();
//     // run blocks until 'q' is pressed
// });
//
// // In the daemon's event loop:
// app.lock().unwrap().trigger_event("agent_detected");
// ```

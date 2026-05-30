//! agentguard-mascot — Guardian Husky pixel-art dog for the terminal.
//!
//! Architecture:
//! - `DogSprite` — owns all animations (idle, walk, happy, sad, surprised)
//! - `DogController` — maps abstract SBS events to animation names
//! - `DogView` — renders the dog in the terminal using ratatui
//! - `App` — wires everything together, exposed `trigger_event()` for SBS
//!
//! # Integration with SBS (Sentinel Behavior System)
//!
//! The mascot is controlled by abstract events sent from the SBS:
//!
//! ```rust,ignore
//! use agentguard_mascot::App;
//!
//! let mut app = App::new();
//!
//! // SBS events trigger animations:
//! app.trigger_event("agent_detected");  // → surprised
//! app.trigger_event("blocked");         // → sad
//! app.trigger_event("all_clear");       // → happy
//! app.trigger_event("scanning");        // → walk
//!
//! app.run()?;  // starts the terminal UI
//! ```

pub mod controller;
pub mod sprite;
pub mod sprites;
pub mod view;

pub use controller::DogController;
pub use sprite::DogSprite;
pub use view::DogView;

/// Main application struct — wires all components together.
pub struct App {
    sprite: DogSprite,
    controller: DogController,
    view: Option<DogView>,
}

impl App {
    pub fn new() -> Self {
        Self {
            sprite: DogSprite::new(),
            controller: DogController::new(),
            view: None,
        }
    }

    /// Called by the external SBS to trigger a mascot behavior.
    /// Returns the animation name that was selected.
    ///
    /// Supported events:
    /// - `"agent_detected"`, `"threat"` → surprised
    /// - `"blocked"`, `"denied"` → sad
    /// - `"all_clear"`, `"protected"`, `"success"` → happy
    /// - `"walk"`, `"scanning"` → walk
    /// - `"idle"`, `"startup"` → idle
    pub fn trigger_event(&mut self, event: &str) -> &str {
        let anim = self.controller.trigger_event(event);
        self.sprite.set_animation(anim);

        if let Some(ref mut view) = self.view {
            view.set_event(event);
            view.set_animation_label(anim);
        }

        anim
    }

    /// Start the terminal render loop. Blocks until user presses 'q'.
    pub fn run(mut self) -> std::io::Result<()> {
        let view = DogView::new(std::mem::take(&mut self.sprite));
        self.view = Some(view);
        let view = self.view.take().unwrap();
        view.run()
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

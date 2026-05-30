//! DogController — maps abstract SBS events to animations.
//!
//! Receives event strings from the external SBS (Sentinel Behavior System)
//! and decides which animation the dog should play.
//!
//! Public API:
//! - trigger_event(&mut self, event: &str) -> Option<&str>
//!   Returns the name of the animation that was triggered, or None.

/// Event → animation mapping used by the controller.
///
/// Events are abstract strings sent by the SBS. The controller maps them
/// to animations. Extend this list to add new behaviors.
///
/// Supported events:
/// - "agent_detected" / "threat" → surprised
/// - "blocked" / "denied" → sad
/// - "all_clear" / "protected" → happy
/// - "walk" / "scanning" → walk
/// - "idle" / "default" → idle
pub struct DogController {
    /// Last animation that was triggered (for external querying).
    last_event: Option<String>,
}

impl DogController {
    pub fn new() -> Self {
        Self { last_event: None }
    }

    /// Process an abstract event from the SBS.
    ///
    /// Returns the animation name that corresponds to the event.
    /// Returns None if the event is not recognized.
    pub fn trigger_event<'a>(&mut self, event: &str) -> &'a str {
        let anim = match event {
            "agent_detected" | "threat" | "intruder" => "surprised",
            "blocked" | "denied" | "access_denied" => "sad",
            "all_clear" | "protected" | "success" | "agent_exited" => "happy",
            "walk" | "scanning" | "patrol" => "walk",
            "idle" | "default" | "startup" | "connected" => "idle",
            _ => "idle",
        };

        self.last_event = Some(event.to_string());
        anim
    }

    /// Get the last triggered event (for debugging / display).
    pub fn last_event(&self) -> Option<&str> {
        self.last_event.as_deref()
    }
}

impl Default for DogController {
    fn default() -> Self {
        Self::new()
    }
}

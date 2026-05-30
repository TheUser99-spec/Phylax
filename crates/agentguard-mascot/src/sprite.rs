//! DogSprite — holds all animations and tracks current animation state.
//!
//! Maintains:
//! - A HashMap of named animations (idle, walk, happy, sad, surprised)
//! - Current animation name, frame index, and timer
//!
//! Public API:
//! - set_animation(&mut self, name: &str) — switch to a different animation
//! - next_frame(&mut self) — advance to next frame based on timer
//! - current_frame(&self) -> &str — get the current frame string

use crate::sprites;
use std::collections::HashMap;
use std::time::Instant;

/// The frame rate for animations — how long each frame is displayed.
const FRAME_MS: u128 = 150;

pub struct DogSprite {
    /// All animations keyed by name.
    animations: HashMap<String, Vec<&'static str>>,
    /// Name of the currently playing animation.
    current_anim: String,
    /// Index within the current animation's frame vector.
    frame_idx: usize,
    /// Last time the frame was advanced.
    last_tick: Instant,
}

impl DogSprite {
    /// Create a new DogSprite with all 5 animations pre-loaded.
    pub fn new() -> Self {
        let mut animations: HashMap<String, Vec<&'static str>> = HashMap::new();
        animations.insert("idle".to_string(), sprites::idle());
        animations.insert("walk".to_string(), sprites::walk());
        animations.insert("happy".to_string(), sprites::happy());
        animations.insert("sad".to_string(), sprites::sad());
        animations.insert("surprised".to_string(), sprites::surprised());

        Self {
            animations,
            current_anim: "idle".to_string(),
            frame_idx: 0,
            last_tick: Instant::now(),
        }
    }

    /// Switch to a different animation. Resets the frame index.
    /// If the name doesn't exist, keeps the current animation.
    pub fn set_animation(&mut self, name: &str) {
        if self.animations.contains_key(name) {
            self.current_anim = name.to_string();
            self.frame_idx = 0;
            self.last_tick = Instant::now();
        }
    }

    /// Advance to the next frame if enough time has passed.
    /// Returns true if the frame changed.
    pub fn next_frame(&mut self) -> bool {
        let elapsed = self.last_tick.elapsed().as_millis();
        if elapsed < FRAME_MS {
            return false;
        }

        let frames = self
            .animations
            .get(&self.current_anim)
            .expect("current_anim must exist in animations map");

        self.frame_idx = (self.frame_idx + 1) % frames.len();
        self.last_tick = Instant::now();
        true
    }

    /// Get the current frame as a &str.
    pub fn current_frame(&self) -> &str {
        self.animations
            .get(&self.current_anim)
            .expect("current_anim must exist in animations map")
            .get(self.frame_idx)
            .copied()
            .unwrap_or("")
    }

    /// Get the width of all sprite frames (in characters).
    pub fn width(&self) -> usize {
        sprites::SPRITE_W
    }

    /// Get the height of all sprite frames (in lines).
    pub fn height(&self) -> usize {
        sprites::SPRITE_H
    }

    /// Get the name of the current animation.
    pub fn current_animation(&self) -> &str {
        &self.current_anim
    }
}

impl Default for DogSprite {
    fn default() -> Self {
        Self::new()
    }
}

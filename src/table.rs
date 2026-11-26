use super::handle::*;

#[track_caller]
fn assert_slot_index(i: usize) {
    assert!(i < SLOTS, "slot index {i} out of range (must be < {SLOTS})");
}

/// Slot state in the context table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CtxSlot {
    /// Free slot.
    Empty,
    /// Object contents have been saved to the backup buffer; there is no matching handle on the chip.
    Saved,
    /// The slot holds an active physical handle.
    Live(u32),
}
#[derive(Clone, Copy)]
pub struct SpaceTable {
    ctx: [CtxSlot; SLOTS],
    /// `0` means an empty slot.
    sessions: [u32; SLOTS],
}
impl SpaceTable {
    pub fn new() -> Self {
        SpaceTable {
            ctx: [CtxSlot::Empty; SLOTS],
            sessions: [0u32; SLOTS],
        }
    }
}

impl Default for SpaceTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SpaceTable {
    /// Mark the slot as empty or saved. These two states do not carry a handle and never violate the
    /// invariant.
    ///
    /// # Panics
    ///
    /// Panics if `i` is outside the fixed slot range.
    pub fn set_slot_free(&mut self, i: usize, saved: bool) {
        assert_slot_index(i);
        self.ctx[i] = if saved {
            CtxSlot::Saved
        } else {
            CtxSlot::Empty
        };
    }
    /// Mark the slot as live. Requires the handle to be valid and not already registered.
    ///
    /// “Not already registered” is a precondition rather than a runtime check: the call sites (`intern`,
    /// load path) already inspected the table once, and checking again would be wasted work. The injective
    /// property is carried by this precondition without introducing any trust assumption.
    ///
    /// # Panics
    ///
    /// Panics if `i` is outside the fixed slot range.
    pub fn set_slot_live(&mut self, i: usize, p: u32) {
        assert_slot_index(i);
        self.ctx[i] = CtxSlot::Live(p);
    }
    /// Virtual handle → physical handle.
    pub fn resolve(&self, v: u32) -> Option<u32> {
        if !is_transient_exec(v) {
            return None;
        }
        let i = slot_of_exec(v);
        if i >= SLOTS {
            return None;
        }
        match self.ctx[i] {
            CtxSlot::Live(p) => Some(p),
            _ => None,
        }
    }
    /// Physical handle → virtual handle, query-only and no allocation.
    pub fn lookup(&self, p: u32) -> Option<u32> {
        self.ctx
            .iter()
            .position(|&slot| slot == CtxSlot::Live(p))
            .map(vhandle_of_exec)
    }
    /// Allocate an empty slot for a physical handle and return the corresponding virtual handle.
    ///
    /// Returns `None` when the table is full; in that case the caller is obligated to release the physical
    /// handle on the chip, or it will continue to occupy chip resources and can never be referenced again.
    pub fn intern(&mut self, p: u32) -> Option<u32> {
        let i = self.ctx.iter().position(|&slot| slot == CtxSlot::Empty)?;
        self.set_slot_live(i, p);
        Some(vhandle_of_exec(i))
    }
    /// Register a session handle. Returns `false` when the table is full; the caller also has the release
    /// obligation in that case.
    pub fn add_session(&mut self, h: u32) -> bool {
        match self.sessions.iter_mut().find(|slot| **slot == 0) {
            Some(slot) => {
                *slot = h;
                true
            }
            None => false,
        }
    }
    pub fn has_session_exec(&self, h: u32) -> bool {
        self.sessions.contains(&h)
    }
    /// Return the session handle in slot `i`.
    ///
    /// # Panics
    ///
    /// Panics if `i` is outside the fixed slot range.
    pub fn session_at(&self, i: usize) -> u32 {
        assert_slot_index(i);
        self.sessions[i]
    }
    /// Clear the session handle in slot `i`.
    ///
    /// # Panics
    ///
    /// Panics if `i` is outside the fixed slot range.
    pub fn clear_session(&mut self, i: usize) {
        assert_slot_index(i);
        self.sessions[i] = 0;
    }
    /// Return the context slot state at index `i`.
    ///
    /// # Panics
    ///
    /// Panics if `i` is outside the fixed slot range.
    pub fn slot_at(&self, i: usize) -> CtxSlot {
        assert_slot_index(i);
        self.ctx[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "out of range")]
    fn slot_at_panics_on_out_of_range_index() {
        let table = SpaceTable::new();
        table.slot_at(usize::MAX);
    }
}

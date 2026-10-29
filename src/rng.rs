//! Randomness injected by JS, never generated here.
//!
//! The core needs a `RngCore + CryptoRng` for every operation that uses
//! randomness (`identity_card`, `encrypt_for_app_with`, `burn_conversation`,
//! ...). On `wasm32-unknown-unknown` there is no system CSPRNG reachable from
//! here: real entropy comes from JS (through a WebView bridge), 32 bytes at a
//! time, **before** every call that consumes it. A seed is never reused across
//! two operations.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use std::cell::RefCell;

thread_local! {
    /// `None` until JS calls `mb_seed_rng`, and `None` again right after an
    /// operation consumed it, so a second use without a new seed fails
    /// explicitly instead of silently reusing the previous stream.
    static SEME: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
}

/// Called by `mb_seed_rng`: installs a new generator from 32 bytes of real
/// entropy. Overwrites an unconsumed seed if any; that should not happen with
/// correct JS, but it is not an error: the old seed simply disappears unused.
pub fn seed(bytes: [u8; 32]) {
    SEME.with(|cell| {
        *cell.borrow_mut() = Some(ChaCha20Rng::from_seed(bytes));
    });
}

/// Consumes the current generator. `None` if not seeded (or already consumed by
/// a previous operation): the caller must report it to JS as an error, never
/// fall back to a spare seed.
pub fn take() -> Option<ChaCha20Rng> {
    SEME.with(|cell| cell.borrow_mut().take())
}

//! Marshalling conventions across the wasm/JS boundary.
//!
//! No `wasm-bindgen`: JS reads and writes the module's linear memory directly
//! (`instance.exports.memory.buffer`), with pointers and lengths as 32-bit
//! integers. Those are the only primitives bare `WebAssembly` (without glue)
//! can pass, and in a `JSContext` without a DOM nothing else is guaranteed.
//!
//! ## One convention for every function that produces bytes
//!
//! Every exported function returning variable data returns a packed `u64`
//! `(ptr << 32) | len`:
//! - success: `ptr` points to `len` bytes in linear memory, to be read and then
//!   freed with [`mb_dealloc`](crate::mb_dealloc) (exported from `lib.rs`);
//! - error: `ptr == 0` (never a valid pointer: `Box::leak` never produces it)
//!   and `len` is the error code, see [`code_of`].
//!
//! Functions that produce no bytes (only an outcome) return a `u32`: `0` for
//! success, otherwise the same error code. No global "last error" is needed:
//! every call carries its own outcome.
//!
//! ## Error codes
//!
//! `1..=9` follow the declaration order of `keyboard_cipher_core::error::Error`
//! (see [`code_of`]). `90..` are specific to this bridge: cases that need a
//! code here but that the core does not model as `Error` (RNG not seeded,
//! imported blob that is not an identity card, no active session, text not
//! UTF-8).

use zeroize::Zeroize;
use keyboard_cipher_core::error::Error;

pub const ERR_RNG_NOT_SEEDED: u32 = 90;
pub const ERR_NO_SESSION: u32 = 92;
pub const ERR_INVALID_UTF8: u32 = 93;
/// Malformed input from the caller (e.g. a seed that is not 32 bytes): a JS
/// bug, not something user data can cause.
pub const ERR_BAD_INPUT: u32 = 94;

/// Maps `Error` to a stable code for JS. Never distinguish sub-causes of
/// `Crypto` with different codes: the opacity is intended.
pub fn code_of(e: &Error) -> u32 {
    match e {
        Error::Format(_) => 1,
        Error::UnsupportedVersion(_) => 2,
        Error::NotOurBlob => 3,
        Error::Decode => 4,
        Error::Crypto => 5,
        Error::UnknownPeer => 6,
        Error::TierUnsupported => 7,
        Error::OwnMessage => 8,
        Error::Keyring => 9,
        // Added to the core after this bridge: one of our messages whose
        // recipient is still there, but the key it was encrypted to was replaced
        // or burned. A NORMAL outcome like `OwnMessage`; only the user message
        // changes.
        //
        // 10 rather than 8: saying "only the recipient can open it" when the
        // key no longer exists would send the user looking for the wrong cause.
        Error::OwnMessageKeyGone => 10,
    }
}

/// Allocates `len` zeroed bytes in linear memory and returns the pointer. Used
/// by JS to write an input (text, key) before passing it to a function that
/// reads it as `(ptr, len)`.
pub fn alloc(len: usize) -> u32 {
    let boxed: Box<[u8]> = vec![0u8; len].into_boxed_slice();
    Box::leak(boxed).as_mut_ptr() as u32
}

/// Frees a buffer obtained from [`alloc`] or from any successful packed
/// result. `ptr == 0` does nothing: that is an error result, with no bytes to
/// free.
///
/// # Safety
/// The caller must pass exactly the `(ptr, len)` returned by [`alloc`] or by a
/// function that packed a `Vec<u8>` of that length: never an arbitrary pointer,
/// never a different length.
pub unsafe fn dealloc(ptr: u32, len: u32) {
    if ptr == 0 {
        return;
    }
    // SAFETY: see the contract above. `slice_from_raw_parts_mut` builds the fat
    // pointer directly, without an intermediate `&mut [u8]` that would assert
    // guarantees (uniqueness, validity) not yet established at this point.
    unsafe {
        let slice_ptr: *mut [u8] = std::ptr::slice_from_raw_parts_mut(ptr as *mut u8, len as usize);
        let mut boxed = Box::from_raw(slice_ptr);
        // ## Zeroize before freeing, for EVERYTHING
        //
        // Everything passes through this bridge: message plaintext,
        // passphrases, and the 32 identity secret bytes coming out of
        // `mb_import_backup`. Freeing without overwriting left them in the
        // module's linear memory until something else overwrote them, and wasm
        // linear memory is never returned to the OS: it stays in the process
        // for the whole run of the script.
        //
        // Done in ONE place, here, rather than in every caller: it is the one
        // path every buffer takes, so the rule cannot be forgotten. The cost is
        // a write of a few dozen bytes per call.
        //
        // `zeroize` rather than `fill(0)`: a write the compiler is not allowed
        // to eliminate.
        boxed.zeroize();
        drop(boxed);
    }
}

/// Packs `(ptr, len)` into one `u64`. wasm32 pointers are 32 bits, so they fit
/// whole in the high half.
fn pack(ptr: u32, len: u32) -> u64 {
    ((ptr as u64) << 32) | (len as u64)
}

/// Moves a `Vec<u8>` into persistent linear memory (outside Rust's control
/// until JS calls [`dealloc`]) and returns the packed success reference.
pub fn pack_ok(data: Vec<u8>) -> u64 {
    let boxed = data.into_boxed_slice();
    let len = boxed.len() as u32;
    let ptr = Box::leak(boxed).as_mut_ptr() as u32;
    pack(ptr, len)
}

/// Packs an error outcome: `ptr = 0`, so the caller can tell it from success.
pub fn pack_err(code: u32) -> u64 {
    pack(0, code)
}

pub fn pack_core_err(e: Error) -> u64 {
    pack_err(code_of(&e))
}

/// Reads a buffer written by JS. Does not take ownership: whoever wrote it
/// (usually via [`alloc`]) must free it with [`dealloc`] after the call.
///
/// # Safety
/// `ptr` must point to at least `len` valid bytes in the current module's
/// linear memory.
pub unsafe fn read_slice<'a>(ptr: u32, len: u32) -> &'a [u8] {
    // SAFETY: see the contract above.
    unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) }
}

/// Like [`read_slice`], but requires valid UTF-8. Returns `None` otherwise; the
/// caller translates that into [`ERR_INVALID_UTF8`].
///
/// # Safety
/// Same contract as [`read_slice`].
pub unsafe fn read_str<'a>(ptr: u32, len: u32) -> Option<&'a str> {
    // SAFETY: see the contract above.
    std::str::from_utf8(unsafe { read_slice(ptr, len) }).ok()
}

/// Reads exactly 32 bytes at `ptr` (a key, public or private).
///
/// # Safety
/// `ptr` must point to at least 32 valid bytes.
pub unsafe fn read_key32<'a>(ptr: u32) -> &'a [u8; 32] {
    // SAFETY: see the contract above.
    unsafe { &*(ptr as *const [u8; 32]) }
}

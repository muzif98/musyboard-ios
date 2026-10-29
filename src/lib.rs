//! WebAssembly bridge to `keyboard-cipher-core`, for running inside Scriptable
//! (iOS). Same role as the core's `jni/` crate for Android, with differences due
//! to the platform:
//!
//! - **No `catch_unwind`.** `jni/` wraps every entry point because Android
//!   supports unwinding and a Rust panic crossing an `extern` boundary is UB.
//!   On `wasm32-unknown-unknown` there is no unwinding: a panic aborts the wasm
//!   instance (trap), and there is nothing to catch here. That is why the JS
//!   side wraps every call in `try/catch` and, on an exception, discards the
//!   instance and recreates it from `config.json`: the canonical state always
//!   lives outside this module.
//! - **RNG injected by JS, not a native `OsRng`.** See `rng.rs`.
//! - **No persistence here.** `wasm32-unknown-unknown` has no filesystem: every
//!   Scriptable run rehydrates the state from `config.json` by calling
//!   `mb_load_identity` + N × `mb_restore_peer`/`mb_restore_prekey_record` +
//!   `mb_finish_load`.
//!
//! ## Marshalling conventions
//!
//! See `marshal` for the protocol (32-bit pointers/lengths, results packed into
//! 64 bits) and `codec` for the layout of each structure. No `wasm-bindgen`: JS
//! calls these `extern "C"` functions directly on `instance.exports`, reading
//! and writing `instance.exports.memory.buffer`.

mod codec;
mod keyring;
mod marshal;
mod rng;

use std::cell::RefCell;

use keyboard_cipher_core::api::Session;
use keyboard_cipher_core::backup;
use keyboard_cipher_core::keys::{Fingerprint, Identity, PublicKey};
use rand_core::RngCore;

use keyring::IosKeyring;

/// Fixed constant in place of Android's "app package": on iOS there is no app
/// from which to infer the recipient, so a single slot is used, as `cli/` does
/// with its own `APP` constant.
const APP: &str = "ios-scriptable";

thread_local! {
    static SESSION: RefCell<Option<Session<IosKeyring>>> = const { RefCell::new(None) };
    /// Identity + keyring being built while rehydrating from `config.json`,
    /// before they become an installed `Session`. Needed because `Session` does
    /// not expose its keyring for writing (only its methods mutate it, on
    /// purpose): a bulk restore must build the keyring BEFORE wrapping it in a
    /// `Session`.
    static PENDING: RefCell<Option<(Identity, IosKeyring)>> = const { RefCell::new(None) };
}

fn install_session(identity: Identity, keyring: IosKeyring) {
    SESSION.with(|cell| *cell.borrow_mut() = Some(Session::new(identity, keyring)));
}

fn with_session<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Session<IosKeyring>) -> R,
{
    SESSION.with(|cell| cell.borrow_mut().as_mut().map(f))
}

fn start_pending(identity: Identity) {
    PENDING.with(|cell| *cell.borrow_mut() = Some((identity, IosKeyring::default())));
}

fn with_pending_keyring<F>(f: F) -> Option<()>
where
    F: FnOnce(&mut IosKeyring),
{
    PENDING.with(|cell| match cell.borrow_mut().as_mut() {
        Some((_, keyring)) => {
            f(keyring);
            Some(())
        }
        None => None,
    })
}

fn finish_pending() -> Option<()> {
    match PENDING.with(|cell| cell.borrow_mut().take()) {
        Some((identity, keyring)) => {
            install_session(identity, keyring);
            Some(())
        }
        None => None,
    }
}

// ---------------------------------------------------------------------------
// Allocator
// ---------------------------------------------------------------------------

/// Allocates `len` bytes in linear memory, for an input JS will write before
/// passing it to another function.
#[no_mangle]
pub extern "C" fn mb_alloc(len: u32) -> u32 {
    marshal::alloc(len as usize)
}

/// Frees a buffer obtained from [`mb_alloc`] or from a successful packed
/// result. Must be called on inputs after use too, not only on outputs.
#[no_mangle]
pub extern "C" fn mb_dealloc(ptr: u32, len: u32) {
    // SAFETY: contract documented on `marshal::dealloc`; holds for every
    // (ptr, len) returned by this module, never for arbitrary pointers.
    unsafe { marshal::dealloc(ptr, len) };
}

// ---------------------------------------------------------------------------
// RNG
// ---------------------------------------------------------------------------

/// Installs 32 bytes of real entropy (from the WebView bridge on the JS side)
/// as the seed for the next operation that consumes randomness. Must be called
/// before EVERY such operation, not once only, because [`rng::take`] consumes
/// the seed and there is no spare.
#[no_mangle]
pub extern "C" fn mb_seed_rng(ptr: u32, len: u32) -> u32 {
    if len != 32 {
        return marshal::ERR_BAD_INPUT;
    }
    // SAFETY: `len == 32` checked above.
    let bytes = unsafe { marshal::read_key32(ptr) };
    rng::seed(*bytes);
    0
}

// ---------------------------------------------------------------------------
// Identity / session lifecycle
// ---------------------------------------------------------------------------

/// Generates a new identity and immediately installs a session with an empty
/// keyring (a new identity has no contacts to restore). Consumes randomness.
///
/// Returns 64 bytes: 32 of secret + 32 of public key. **The secret leaves in
/// clear on purpose**: it is the only way for JS to persist it in
/// `config.json`, exactly as `nativeGenerateSecret` does in `jni/`.
#[no_mangle]
pub extern "C" fn mb_generate_identity() -> u64 {
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let identity = match Identity::from_secret_bytes(secret) {
        Ok(i) => i,
        Err(e) => return marshal::pack_core_err(e),
    };
    let public = *identity.public().as_bytes();
    install_session(identity, IosKeyring::default());

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&secret);
    out.extend_from_slice(&public);
    marshal::pack_ok(out)
}

/// Starts restoring an already persisted identity: the session is NOT installed
/// yet, and must be completed with N × [`mb_restore_peer`] /
/// [`mb_restore_prekey_record`] and finally [`mb_finish_load`].
///
/// Returns the public key (32 bytes) on success.
#[no_mangle]
pub extern "C" fn mb_load_identity(secret_ptr: u32) -> u64 {
    // SAFETY: the caller guarantees 32 valid bytes at `secret_ptr`.
    let bytes = unsafe { marshal::read_key32(secret_ptr) };
    let identity = match Identity::from_secret_bytes(*bytes) {
        Ok(i) => i,
        Err(e) => return marshal::pack_core_err(e),
    };
    let public = identity.public().as_bytes().to_vec();
    start_pending(identity);
    marshal::pack_ok(public)
}

/// Restores a contact during rehydration. Called after [`mb_load_identity`] and
/// before [`mb_finish_load`].
#[no_mangle]
pub extern "C" fn mb_restore_peer(ptr: u32, len: u32) -> u32 {
    // SAFETY: the caller guarantees `len` valid bytes at `ptr`.
    let buf = unsafe { marshal::read_slice(ptr, len) };
    let Some(record) = codec::decode_peer_record(buf) else {
        return marshal::ERR_BAD_INPUT;
    };
    match with_pending_keyring(|kr| kr.restore_peer(record)) {
        Some(()) => 0,
        None => marshal::ERR_NO_SESSION,
    }
}

/// Restores chain/epoch state for a contact during rehydration. Same window as
/// [`mb_restore_peer`].
#[no_mangle]
pub extern "C" fn mb_restore_prekey_record(ptr: u32, len: u32) -> u32 {
    // SAFETY: the caller guarantees `len` valid bytes at `ptr`.
    let buf = unsafe { marshal::read_slice(ptr, len) };
    let Some(record) = codec::decode_prekey_record(buf) else {
        return marshal::ERR_BAD_INPUT;
    };
    match with_pending_keyring(|kr| kr.restore_prekey(record)) {
        Some(()) => 0,
        None => marshal::ERR_NO_SESSION,
    }
}

/// Completes rehydration: installs the session built by [`mb_load_identity`]
/// and the intermediate restores. From here on the other functions
/// (encrypt/decrypt/...) become usable.
#[no_mangle]
pub extern "C" fn mb_finish_load() -> u32 {
    match finish_pending() {
        Some(()) => 0,
        None => marshal::ERR_NO_SESSION,
    }
}

// ---------------------------------------------------------------------------
// Reading state for persistence (rewriting config.json)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn mb_dump_peers_count() -> u32 {
    with_session(|s| u32::try_from(s.keyring().peer_records().len()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn mb_dump_peer_at(i: u32) -> u64 {
    match with_session(|s| {
        s.keyring()
            .peer_records()
            .get(i as usize)
            .map(codec::encode_peer_record)
    }) {
        Some(Some(bytes)) => marshal::pack_ok(bytes),
        Some(None) => marshal::pack_err(marshal::ERR_BAD_INPUT),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

#[no_mangle]
pub extern "C" fn mb_dump_prekey_count() -> u32 {
    with_session(|s| u32::try_from(s.keyring().prekey_dump().len()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn mb_dump_prekey_at(i: u32) -> u64 {
    match with_session(|s| {
        s.keyring()
            .prekey_dump()
            .get(i as usize)
            .map(codec::encode_prekey_record)
    }) {
        Some(Some(bytes)) => marshal::pack_ok(bytes),
        Some(None) => marshal::pack_err(marshal::ERR_BAD_INPUT),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

// ---------------------------------------------------------------------------
// Identity to show / verify
// ---------------------------------------------------------------------------

/// Identity card blob (`kc/...`) for an Android contact. Consumes randomness
/// (the core uses it for the length padding).
#[no_mangle]
pub extern "C" fn mb_identity_card() -> u64 {
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    match with_session(|s| s.identity_card(&mut rng)) {
        Some(card) => marshal::pack_ok(card.into_bytes()),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

#[no_mangle]
pub extern "C" fn mb_my_fingerprint() -> u64 {
    match with_session(|s| s.my_fingerprint().display()) {
        Some(fp) => marshal::pack_ok(fp.into_bytes()),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Our own public key (32 bytes). Needed after [`mb_import_backup`]: a backup
/// carries only the secret, and without this there is no way to recover the
/// public key for `config.json` without computing it elsewhere.
#[no_mangle]
pub extern "C" fn mb_my_public() -> u64 {
    match with_session(|s| *s.identity().public().as_bytes()) {
        Some(bytes) => marshal::pack_ok(bytes.to_vec()),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Fingerprint of any key, not only our own (e.g. a contact just imported).
/// Needs no active session: it is a pure function of the key.
#[no_mangle]
pub extern "C" fn mb_fingerprint_of(peer_ptr: u32) -> u64 {
    // SAFETY: the caller guarantees 32 valid bytes at `peer_ptr`.
    let bytes = unsafe { marshal::read_key32(peer_ptr) };
    let peer = PublicKey::from_bytes(*bytes);
    marshal::pack_ok(codec::encode_fingerprint(&Fingerprint::of(&peer)))
}

// ---------------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn mb_set_current_peer(peer_ptr: u32) -> u32 {
    // SAFETY: the caller guarantees 32 valid bytes at `peer_ptr`.
    let bytes = unsafe { marshal::read_key32(peer_ptr) };
    let peer = PublicKey::from_bytes(*bytes);
    match with_session(|s| s.set_current_peer(APP, &peer)) {
        Some(Ok(())) => 0,
        Some(Err(e)) => marshal::code_of(&e),
        None => marshal::ERR_NO_SESSION,
    }
}

/// The current recipient, if any, to show in the UI before encrypting.
///
/// Unlike the other producing functions, no recipient is NOT an error here:
/// `Session::current_peer` returns an `Option`, not a `Result`. `(ptr=0,
/// len=0)` distinguishes it from a real error, which always has `len > 0`
/// (codes are all in `1..=9` or `90..`, never `0`).
#[no_mangle]
pub extern "C" fn mb_current_peer() -> u64 {
    match with_session(|s| s.current_peer(APP).cloned()) {
        Some(Some(peer)) => marshal::pack_ok(peer.as_bytes().to_vec()),
        Some(None) => 0, // pack(0, 0): no recipient, not an error.
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Encrypts with an epoch (decision J, forward secrecy off: `effimero =
/// false`) for the current recipient. Consumes randomness.
#[no_mangle]
pub extern "C" fn mb_encrypt(text_ptr: u32, text_len: u32, now_unix: i64) -> u64 {
    // SAFETY: the caller guarantees `text_len` valid bytes at `text_ptr`.
    let plaintext = unsafe { marshal::read_slice(text_ptr, text_len) };
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    match with_session(|s| s.encrypt_for_app_with(APP, plaintext, now_unix, &mut rng, false)) {
        Some(Ok(blob)) => marshal::pack_ok(blob.into_bytes()),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Recognises and opens incoming text: message, burn, or **identity card**.
/// The core routes all of them through the same entry point, so no separate
/// function is needed to import a contact. The tag in the result (see
/// `codec::TAG_*`) says which case it is.
#[no_mangle]
pub extern "C" fn mb_decrypt(text_ptr: u32, text_len: u32, now_unix: i64) -> u64 {
    // SAFETY: the caller guarantees `text_len` valid bytes at `text_ptr`.
    let text = match unsafe { marshal::read_str(text_ptr, text_len) } {
        Some(t) => t,
        None => return marshal::pack_err(marshal::ERR_INVALID_UTF8),
    };
    match with_session(|s| s.handle_incoming_text(APP, text, now_unix)) {
        Some(Ok(item)) => marshal::pack_ok(codec::encode_incoming_item(&item)),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Burn (decision J): produces the request blob and immediately destroys the
/// local keys for that contact. Consumes randomness.
#[no_mangle]
pub extern "C" fn mb_burn_conversation(peer_ptr: u32, now_unix: i64) -> u64 {
    // SAFETY: the caller guarantees 32 valid bytes at `peer_ptr`.
    let bytes = unsafe { marshal::read_key32(peer_ptr) };
    let peer = PublicKey::from_bytes(*bytes);
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    match with_session(|s| s.burn_conversation(&peer, now_unix, &mut rng)) {
        Some(Ok(blob)) => marshal::pack_ok(blob.into_bytes()),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

#[no_mangle]
pub extern "C" fn mb_assign_label(peer_ptr: u32, label_ptr: u32, label_len: u32) -> u64 {
    // SAFETY: the caller guarantees 32 valid bytes at `peer_ptr`.
    let peer_bytes = unsafe { marshal::read_key32(peer_ptr) };
    let peer = PublicKey::from_bytes(*peer_bytes);
    // SAFETY: the caller guarantees `label_len` valid bytes at `label_ptr`.
    let label = match unsafe { marshal::read_str(label_ptr, label_len) } {
        Some(l) => l,
        None => return marshal::pack_err(marshal::ERR_INVALID_UTF8),
    };
    match with_session(|s| s.assign_label(&peer, label)) {
        Some(Ok(outcome)) => marshal::pack_ok(codec::encode_label_outcome(&outcome)),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Confirms a key change after a `LabelOutcome::Conflict` shown to the user.
/// Never automatic.
#[no_mangle]
pub extern "C" fn mb_confirm_key_change(old_ptr: u32, new_ptr: u32, now_unix: i64) -> u32 {
    // SAFETY: the caller guarantees 32 valid bytes at each pointer.
    let old = PublicKey::from_bytes(*unsafe { marshal::read_key32(old_ptr) });
    let new = PublicKey::from_bytes(*unsafe { marshal::read_key32(new_ptr) });
    match with_session(|s| s.confirm_key_change(&old, &new, now_unix)) {
        Some(Ok(())) => 0,
        Some(Err(e)) => marshal::code_of(&e),
        None => marshal::ERR_NO_SESSION,
    }
}

/// Forgets a contact: removes the TOFU pin and temporary keys towards them, and
/// stops using them as current recipient. `Session::forget_peer` does both on
/// purpose: forgetting only from the keyring would leave the current recipient
/// pointing at an unpinned key. The boolean outcome ("was it there?") is not
/// needed by JS, which always calls on a contact chosen from a list.
#[no_mangle]
pub extern "C" fn mb_forget_peer(peer_ptr: u32) -> u32 {
    // SAFETY: the caller guarantees 32 valid bytes at `peer_ptr`.
    let peer = PublicKey::from_bytes(*unsafe { marshal::read_key32(peer_ptr) });
    match with_session(|s| s.forget_peer(&peer)) {
        Some(Ok(_)) => 0,
        Some(Err(e)) => marshal::code_of(&e),
        None => marshal::ERR_NO_SESSION,
    }
}

#[no_mangle]
pub extern "C" fn mb_mark_verified(peer_ptr: u32) -> u32 {
    // SAFETY: the caller guarantees 32 valid bytes at `peer_ptr`.
    let peer = PublicKey::from_bytes(*unsafe { marshal::read_key32(peer_ptr) });
    match with_session(|s| s.mark_verified(&peer)) {
        Some(Ok(())) => 0,
        Some(Err(e)) => marshal::code_of(&e),
        None => marshal::ERR_NO_SESSION,
    }
}

// ---------------------------------------------------------------------------
// Passphrase-encrypted backup (Argon2id, `keyboard_cipher_core::backup`).
//
// The keyring is OPAQUE bytes for `backup::export`/`import`. No new
// serialisation is invented here: JS builds the blob with the same codec used
// for `config.json` (`encodePeerRecordJs`/`encodePrekeyRecordJs`, with a length
// prefix per record), passes it to `mb_export_backup` and gets it back from
// `mb_import_backup`; this crate treats it as bytes, as the core does.
// ---------------------------------------------------------------------------

/// Encrypts identity + keyring (opaque bytes from JS) with a passphrase.
/// Consumes randomness (salt and nonce).
#[no_mangle]
pub extern "C" fn mb_export_backup(
    pass_ptr: u32,
    pass_len: u32,
    keyring_ptr: u32,
    keyring_len: u32,
) -> u64 {
    // SAFETY: the caller guarantees the declared lengths at the pointers.
    let passphrase = unsafe { marshal::read_slice(pass_ptr, pass_len) };
    // SAFETY: as above.
    let keyring_bytes = unsafe { marshal::read_slice(keyring_ptr, keyring_len) };
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    match with_session(|s| backup::export(s.identity(), keyring_bytes, passphrase, &mut rng)) {
        Some(Ok(blob)) => marshal::pack_ok(blob),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

/// Opens a backup. Returns 32 bytes of secret + the opaque keyring
/// (concatenated); installs no session by itself. The caller continues with
/// `mb_load_identity` + N × `mb_restore_peer`/`mb_restore_prekey_record`
/// (decoding the keyring with the codec it was built with) + `mb_finish_load`,
/// as for rehydration from `config.json`. Needs no active session.
#[no_mangle]
pub extern "C" fn mb_import_backup(pass_ptr: u32, pass_len: u32, blob_ptr: u32, blob_len: u32) -> u64 {
    // SAFETY: the caller guarantees the declared lengths at the pointers.
    let passphrase = unsafe { marshal::read_slice(pass_ptr, pass_len) };
    // SAFETY: as above.
    let blob = unsafe { marshal::read_slice(blob_ptr, blob_len) };
    match backup::import(blob, passphrase) {
        Ok(opened) => {
            let mut out = Vec::with_capacity(32usize.saturating_add(opened.keyring.len()));
            out.extend_from_slice(opened.secret.as_ref());
            out.extend_from_slice(&opened.keyring);
            marshal::pack_ok(out)
        }
        Err(e) => marshal::pack_core_err(e),
    }
}

// ---------------------------------------------------------------------------
// Attachments (`keyboard_cipher_core::file`). Unlike text messages, which are
// encrypted with an epoch here (decision J, `effimero = false`), attachments
// ALWAYS use the forward secrecy chain (decision I), as the core recommends:
// an attachment without the chain is a bigger hole than a message without it.
// They share the chain with messages: same one-to-one conversation.
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn mb_encrypt_file(
    peer_ptr: u32,
    name_ptr: u32,
    name_len: u32,
    mime_ptr: u32,
    mime_len: u32,
    content_ptr: u32,
    content_len: u32,
    now_unix: i64,
) -> u64 {
    // SAFETY: the caller guarantees 32 valid bytes at `peer_ptr`.
    let peer = PublicKey::from_bytes(*unsafe { marshal::read_key32(peer_ptr) });
    // SAFETY: the caller guarantees `name_len` valid bytes at `name_ptr`.
    let name = match unsafe { marshal::read_str(name_ptr, name_len) } {
        Some(s) => s.to_owned(),
        None => return marshal::pack_err(marshal::ERR_INVALID_UTF8),
    };
    // SAFETY: the caller guarantees `mime_len` valid bytes at `mime_ptr`.
    let mime = match unsafe { marshal::read_str(mime_ptr, mime_len) } {
        Some(s) => s.to_owned(),
        None => return marshal::pack_err(marshal::ERR_INVALID_UTF8),
    };
    // SAFETY: the caller guarantees `content_len` valid bytes at `content_ptr`.
    let content = unsafe { marshal::read_slice(content_ptr, content_len) };
    let meta = keyboard_cipher_core::file::FileMeta { name, mime };
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    match with_session(|s| s.encrypt_file_with(&peer, &meta, content, now_unix, &mut rng, true)) {
        Some(Ok(blob)) => marshal::pack_ok(blob),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

#[no_mangle]
pub extern "C" fn mb_decrypt_file(bytes_ptr: u32, bytes_len: u32, now_unix: i64) -> u64 {
    // SAFETY: the caller guarantees `bytes_len` valid bytes at `bytes_ptr`.
    let bytes = unsafe { marshal::read_slice(bytes_ptr, bytes_len) };
    match with_session(|s| s.handle_incoming_file(bytes, now_unix)) {
        Some(Ok(incoming)) => marshal::pack_ok(codec::encode_incoming_file(&incoming)),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

// ---------------------------------------------------------------------------
// Group messages (decision K). Only encryption needs a dedicated function: an
// incoming group goes through the same `handle_incoming_text`/`mb_decrypt` as a
// one-to-one message. The core recognises it (`ParsedBlob::Group`) and produces
// the same `IncomingItem::Message`, with `gruppo=true` and `destinatari=N`,
// already encoded by `codec::encode_incoming_item`. No forward secrecy, by
// decision K1.
// ---------------------------------------------------------------------------

/// Encrypts for several recipients. `peers_ptr` points to `peers_count * 32`
/// bytes (concatenated keys, no separator). Consumes randomness.
#[no_mangle]
pub extern "C" fn mb_encrypt_group(
    peers_ptr: u32,
    peers_count: u32,
    text_ptr: u32,
    text_len: u32,
    now_unix: i64,
) -> u64 {
    // SAFETY: the caller guarantees `peers_count * 32` valid bytes at `peers_ptr`.
    let raw = unsafe { marshal::read_slice(peers_ptr, peers_count.saturating_mul(32)) };
    let mut destinatari = Vec::with_capacity(peers_count as usize);
    for chunk in raw.chunks_exact(32) {
        let Ok(arr): std::result::Result<[u8; 32], _> = chunk.try_into() else {
            return marshal::pack_err(marshal::ERR_BAD_INPUT);
        };
        destinatari.push(PublicKey::from_bytes(arr));
    }
    // SAFETY: the caller guarantees `text_len` valid bytes at `text_ptr`.
    let plaintext = unsafe { marshal::read_slice(text_ptr, text_len) };
    let mut rng = match rng::take() {
        Some(r) => r,
        None => return marshal::pack_err(marshal::ERR_RNG_NOT_SEEDED),
    };
    match with_session(|s| s.encrypt_group(&destinatari, plaintext, now_unix, &mut rng)) {
        Some(Ok(blob)) => marshal::pack_ok(blob.into_bytes()),
        Some(Err(e)) => marshal::pack_core_err(e),
        None => marshal::pack_err(marshal::ERR_NO_SESSION),
    }
}

#[cfg(test)]
// Same exemption as the core: in a test a panic is how failure is reported.
// `expect_used` too (messages make it clear which assertion failed) and
// `arithmetic_side_effects` (sums of test timestamps never overflow, but the
// lint cannot tell).
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests;

# MusyBoard for iOS

End-to-end encryption of [MusyBoard](https://github.com/muzif98/musyboard-android)
on iPhone, without writing an iOS app.

On iOS a system keyboard cannot do what MusyBoard does on Android, and the App
Store is not a realistic route for this project. So the approach is different:
**the very same Rust core**
([musyboard-core](https://github.com/muzif98/musyboard-core)), compiled to
WebAssembly and run inside [Scriptable](https://scriptable.app/), an offline
JavaScript engine for iOS, driven by two Shortcuts.

Same core means the same wire format: an iPhone and an Android phone write to
each other without knowing about each other.

> **Status: experimental.** Everything was built and verified without an
> iPhone (Rust tests on the host, cross-language test vectors, JavaScript tests
> under QuickJS, the QR encoder compared against a reference library). The
> WebAssembly runtime and the entropy bridge were confirmed on a real device
> with the proof of concept in `poc/`, but the full end-to-end flow still has
> to be tested on a device. See [INSTALL.md](INSTALL.md).

## What is inside

| Path | Contents |
|---|---|
| `src/` | The `musyboard-wasm` crate: `mb_*` functions exported to JavaScript, no `wasm-bindgen`, hand-written marshalling with 32-bit pointers and lengths |
| `scriptable/MusyBoard.js` | The Scriptable script: UI, storage, the bridge to the wasm module, hand-written UTF-8/Base64 and QR code encoder |
| `scriptable/test-*.js` | Tests for the pure JavaScript logic, runnable in any JS engine |
| `dist/musyboard_wasm.wasm` | The prebuilt module to copy to the iPhone (see [dist/README.md](dist/README.md)) |
| `build-wasm.sh` | Reproducible build of the module, with build-machine paths stripped |
| `poc/` | Phase 0 proof of concept, kept because it documents what was verified on a real iPhone |
| [INSTALL.md](INSTALL.md) | Installing Scriptable, the two Shortcuts, and the end-to-end check |
| [DESIGN.md](DESIGN.md) | Design decisions specific to this bridge |

The user interface of the script is in Italian.

## How it works

```text
Shortcut ──text──▶ MusyBoard.js (Scriptable) ──bytes──▶ musyboard_wasm.wasm
                        │                                  (the Rust core)
                        └── config.json (local Scriptable folder)
```

- **Two Shortcuts**: "decrypt" (available from the share sheet) and
  "encrypt" (reads the clipboard, copies the result back). Each prefixes its
  input with a marker (`MB_DECRYPT:` / `MB_ENCRYPT:`) so the script never has
  to guess the intent.
- **The wasm module has zero imports**: `WebAssembly.instantiate(bytes, {})`
  is enough, nothing is requested from the host.
- **Randomness comes from iOS** through a hidden WebView
  (`crypto.getRandomValues`), 32 bytes before every operation that needs it;
  the Rust side refuses to reuse a seed.
- **State lives in `config.json`** in Scriptable's local folder, rewritten
  through a recoverable `.new`/`.bak` journal. Each run rehydrates the core
  from it.
- **No network access** anywhere in the script.

Text messages use the burnable epoch scheme (rereadable history that can be
destroyed on request); attachments use the forward secrecy chain. See the
core's [DESIGN.md](https://github.com/muzif98/musyboard-core/blob/main/DESIGN.md)
for what these mean.

## Security note: the private key is stored in clear

On Android the identity secret is wrapped by Android Keystore and is useless
off that phone. Here it is stored in `config.json`, in Base64, in clear.

What still protects it: the file lives in Scriptable's sandbox, so no other app
can read it; it is in `FileManager.local()`, so it does **not** sync to iCloud
Drive; and iOS encrypts it at rest with the device passcode.

What does not: **a device backup** (iCloud or computer) contains the private
key as it is. Scriptable offers no way to exclude a file from backups and no
Keystore equivalent. Encrypting `config.json` with a passphrase would be
possible (the core has Argon2id for backups) but would mean asking for it on
every use; that is a product decision, not something to change silently.

As long as this holds: **an iPhone is worth as much as its backup.**

## Building

The crate depends on the core checked out next to it:

```text
musyboard-core/    the core
musyboard-ios/     this repository
```

```sh
cargo test                                  # Rust tests, on the host
cargo clippy --all-targets -- -D warnings
./build-wasm.sh                             # builds and updates dist/
./build-wasm.sh --check                     # fails if dist/ is out of date
```

`build-wasm.sh` remaps build-machine paths (cargo registry, checkouts) to fixed
names, so the published binary contains nothing about the machine that built it
and the same toolchain gives the same bytes.

Changes to the core's `Error`, `format.rs` or public signatures must be rebuilt
here too. The core's `verify-all.sh` builds this crate, runs the Rust and
JavaScript tests, checks that the module has no imports and that `dist/` matches
the source.

JavaScript tests run outside Scriptable, in any engine, by concatenating the
script and the test:

```sh
cat scriptable/MusyBoard.js scriptable/test-codec.js | node --input-type=module
```

## License

GPL-3.0-only. See [LICENSE](LICENSE).

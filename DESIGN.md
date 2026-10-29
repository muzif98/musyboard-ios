# Design decisions (iOS bridge)

The cryptographic design is in the core's
[DESIGN.md](https://github.com/muzif98/musyboard-core/blob/main/DESIGN.md).
This file covers only what is specific to running the core inside Scriptable.

## Why Scriptable and WebAssembly

A third-party keyboard on iOS cannot do what MusyBoard does on Android, and
distributing through the App Store is not a realistic route for this project.
Scriptable is an offline JavaScript engine that can load WebAssembly, run from
Shortcuts and the share sheet, and store files in its own sandbox. Compiling the
**same Rust core** to WebAssembly means no second implementation of the format:
a cryptographic fix in the core reaches iOS by rebuilding.

The cost: this bridge lives in its own repository, so a change to the core's
public API is not updated here in the same commit. That already broke the build
once (a new `Error` variant left a non-exhaustive `match`). The core's
`verify-all.sh` exists to catch that.

## No `wasm-bindgen`, hand-written marshalling

JavaScript calls the exported `mb_*` functions directly on
`instance.exports`, reading and writing `instance.exports.memory.buffer`.
Pointers and lengths are 32-bit integers, the only primitives bare
WebAssembly can pass. Every function returning data returns a packed `u64`
`(ptr << 32) | len`; `ptr == 0` means error and `len` is the error code. There
is no global "last error".

The module has **zero imports**, so it loads with
`WebAssembly.instantiate(bytes, {})`, which was verified on a real device in
the proof of concept.

## No `catch_unwind`

The Android bridge wraps every entry point in `catch_unwind` because unwinding
across an `extern` boundary is undefined behaviour. On
`wasm32-unknown-unknown` there is no unwinding: a panic traps the instance. The
script therefore wraps every call in `try/catch` and, on an exception, discards
the instance and recreates it from `config.json`. The canonical state always
lives outside the module.

## Randomness injected from JavaScript

There is no system CSPRNG reachable from `wasm32-unknown-unknown`. Real entropy
comes from `crypto.getRandomValues` inside a hidden WebView, 32 bytes before
**every** operation that needs randomness. The Rust side consumes the seed on
use, so a second operation without a fresh seed fails explicitly instead of
reusing the stream.

The bridge is the one part that depends on WKWebView behaviour. Its worst
failure would be silent: a WebView returning a cached value, so two operations
would get the same seed, i.e. the same ephemeral key and nonce. The script
therefore checks every seed (length, a stuck constant value, equality with the
previous one) and stops with a readable error rather than encrypting with fake
entropy. These checks are synchronous and separate so they can be tested
outside iOS.

## Hand-written UTF-8, Base64 and QR code

`TextEncoder`, `TextDecoder`, `atob` and `btoa` are DOM APIs, not part of the
JavaScript language, and are not guaranteed in Scriptable's JSContext. The
script uses only ECMAScript (`Uint8Array`, `DataView`, `String.fromCodePoint`).

The QR encoder (byte mode, level M, fixed mask 0) is written by hand to avoid
any library or network access. Its tables were extracted mechanically from a
reference implementation, and its output was compared matrix by matrix against
that implementation on about 400 inputs. That comparison found four real bugs
that were invisible when reading the code (an ordering issue between reserved
areas and the timing pattern, a Python `a[-0]` indexing subtlety, a mutated
loop variable, and unconditional byte-alignment padding).

The QR code is **shown, never scanned**, consistently with the Android app,
which has no camera permission: the other person scans it with any reader.

## State and persistence

`config.json` is written through a journal: the new state is written to
`config.json.new` and read back, the old file is moved to `config.json.bak`,
then the new one is moved into place. Scriptable has `move` but no atomic
replace; the journal makes every interruption recoverable, and the loader picks
the newest valid generation.

## Text messages use epochs, attachments use the chain

Text messages are encrypted with the epoch scheme (decision J): history stays
rereadable on the phone until the conversation is burned. Attachments always
use the forward secrecy chain (decision I), as the core recommends: a file is a
bigger exposure than a line of text. Both share the same per-contact state.

## UI

The interface uses Scriptable's `Alert` dialogs rather than `UITable`: with a
few contacts, button dialogs are simpler to keep correct. Group messages never
show an author (decision K6); one-to-one messages show the sender, whether the
key was just pinned, and whether it was verified in person.

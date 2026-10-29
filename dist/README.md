# `musyboard_wasm.wasm`

The module to copy to the iPhone, committed **on purpose** even though it is a
build artefact: whoever installs it should be able to take the file without a
Rust toolchain and the `wasm32-unknown-unknown` target.

It is a deliberate copy and does not update itself. **After every change to
this crate or to the core it must be rebuilt**, otherwise what goes to the
iPhone does not match the source:

    ./build-wasm.sh

`./build-wasm.sh --check` (also run by the core's `verify-all.sh`) fails if this
file is not what the source produces.

The module must have **zero imports**: Scriptable instantiates it with an empty
import object, and an import section would stop it from loading.

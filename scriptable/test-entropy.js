// Tests for the checks on the entropy seed, OUTSIDE Scriptable.
//
// Loaded like `test-codec.js`: MusyBoard.js first, then this file, in the same
// JS context.
//
// Why these checks have their own test: the entropy bridge is the only part of
// the system that depends on WKWebView behaviour. If it broke, it would break
// silently, and encrypting with fake entropy is the worst failure this project
// could produce.
//
// `controllaSeme` was written synchronous and separate from `freshEntropy32`
// precisely so that it can run here.

let ePassati = 0;
let eFalliti = 0;

function eCheck(nome, ok) {
  if (ok) {
    ePassati++;
  } else {
    eFalliti++;
    print("FALLITO: " + nome);
  }
}

function seme(f) {
  const a = [];
  for (let k = 0; k < 32; k++) a.push(f(k));
  return new Uint8Array(a);
}

function solleva(bytes) {
  try {
    controllaSeme(bytes);
    return false;
  } catch (e) {
    return true;
  }
}

print("--- controlli sul seme di entropia ---");

// A plausible seed passes. Without this, an overly strict check would block
// everything and the test would not notice.
ultimoSeme = null;
eCheck("un seme buono passa", !solleva(seme((k) => (k * 7 + 3) & 255)));

// Wrong lengths: Rust already rejects them, but here the error is readable and
// comes before allocating in wasm memory.
ultimoSeme = null;
eCheck("zero byte", solleva(new Uint8Array(0)));
eCheck("16 byte", solleva(new Uint8Array(16)));
eCheck("33 byte", solleva(new Uint8Array(33)));

// A stuck bridge that always returns the same thing.
ultimoSeme = null;
eCheck("32 zeri", solleva(seme(() => 0)));
ultimoSeme = null;
eCheck("32 byte tutti uguali", solleva(seme(() => 0xab)));

// The case that really matters: a WebView returning a cached value. Two
// operations with the same seed = same ephemeral key and same nonce = keystream
// reuse.
const ripetuto = seme((k) => (k * 13 + 5) & 255);
ultimoSeme = null;
controllaSeme(ripetuto);
ultimoSeme = ripetuto;
eCheck("lo stesso seme due volte viene rifiutato", solleva(ripetuto));

// And a different seed after another passes: the check above must not have
// blocked everything forever.
eCheck("un seme diverso dal precedente passa", !solleva(seme((k) => (k * 29 + 11) & 255)));

print("");
print(ePassati + " passati, " + eFalliti + " falliti");
if (eFalliti > 0) {
  throw new Error(eFalliti + " test sull'entropia falliti");
}

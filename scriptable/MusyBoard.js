// -----------------------------------------------------------------------
// MusyBoard for Scriptable (iOS)
//
// A single script: shows an interactive menu when launched from the
// Scriptable icon, or encrypts/decrypts on the fly when launched from one of
// the two Shortcuts (decrypt and encrypt, see INSTALL.md). The
// Shortcuts pass a parameter prefixed with a marker ("MB_DECRYPT:" or
// "MB_ENCRYPT:"), added by a "Text" action inside the Shortcut itself; see
// the end of this file and INSTALL.md.
//
// PREREQUISITE, in THIS same local Scriptable folder (FileManager.local(),
// NEVER the iCloud folder: the private key would be synced to Apple's
// servers):
//   - musyboard_wasm.wasm   (the module compiled from this repository)
//
// On first run the script creates "config.json" in the same folder. It holds
// the identity (private key IN CLEAR: there is no equivalent of Android
// Keystore here, an explicitly accepted risk, see README) and the contacts and
// chain state.
//
// No network requests in this script. Adding one would be a change to
// evaluate on its own, never something to slip in here.

// -----------------------------------------------------------------------
// Paths
// -----------------------------------------------------------------------

// Computed on first call, not when the file loads: `FileManager` is a
// Scriptable global, absent by construction when this file is loaded elsewhere
// (e.g. `test-codec.js`) only for the pure functions that do not touch the
// filesystem.
let files = null;
let CONFIG_PATH = null;
let CONFIG_TMP_PATH = null;
let CONFIG_BACKUP_PATH = null;
let WASM_PATH = null;

function ensurePaths() {
  if (files) return;
  files = FileManager.local();
  CONFIG_PATH = files.joinPath(files.documentsDirectory(), "config.json");
  // The active state is never overwritten directly: it holds the
  // cryptographic chains, so an interrupted write must not turn it into
  // truncated JSON and lose the identity.
  CONFIG_TMP_PATH = files.joinPath(files.documentsDirectory(), "config.json.new");
  CONFIG_BACKUP_PATH = files.joinPath(files.documentsDirectory(), "config.json.bak");
  WASM_PATH = files.joinPath(files.documentsDirectory(), "musyboard_wasm.wasm");
}

// -----------------------------------------------------------------------
// Hand-written UTF-8 and Base64.
//
// Deliberately NO `TextEncoder`/`TextDecoder`/`atob`/`btoa`: they are
// DOM/Web APIs, not part of the JavaScript engine, and in a JSContext without
// a WebView (which is what runs this script) they are not guaranteed to
// exist. That is also why entropy goes through a hidden WebView rather than a
// global `crypto`. `Uint8Array`/`DataView`/`String.fromCodePoint` are part of
// the language (ECMAScript) and are enough.
// -----------------------------------------------------------------------

function utf8Encode(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.codePointAt(i);
    if (code > 0xffff) i++; // a surrogate pair: consumed in one step
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      bytes.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f)
      );
    }
  }
  return new Uint8Array(bytes);
}

function utf8Decode(bytes) {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i++];
    if (b0 < 0x80) {
      out += String.fromCodePoint(b0);
    } else if ((b0 & 0xe0) === 0xc0) {
      const b1 = bytes[i++];
      out += String.fromCodePoint(((b0 & 0x1f) << 6) | (b1 & 0x3f));
    } else if ((b0 & 0xf0) === 0xe0) {
      const b1 = bytes[i++];
      const b2 = bytes[i++];
      out += String.fromCodePoint(((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f));
    } else {
      const b1 = bytes[i++];
      const b2 = bytes[i++];
      const b3 = bytes[i++];
      out += String.fromCodePoint(
        ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f)
      );
    }
  }
  return out;
}

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base64Encode(bytes) {
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      B64_CHARS[(n >> 18) & 63] +
      B64_CHARS[(n >> 12) & 63] +
      B64_CHARS[(n >> 6) & 63] +
      B64_CHARS[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63] + "==";
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63] + B64_CHARS[(n >> 6) & 63] + "=";
  }
  return out;
}

function base64Decode(str) {
  const clean = str.replace(/[^A-Za-z0-9+/]/g, "");
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const val = B64_CHARS.indexOf(ch);
    if (val === -1) continue;
    buffer = (buffer << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

function concatBytes(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// -----------------------------------------------------------------------
// QR code encoder, offline and hand-written: no library, no network.
//
// Byte mode only, error correction level M, fixed mask 0 (pattern 0,
// (row+column) mod 2 == 0). A fixed mask is legitimate: ISO/IEC 18004 does
// not require trying all of them and picking the best, only applying ONE and
// declaring it correctly in the format bits. Always using mask 0 avoids
// implementing the scoring of the eight variants.
//
// The numeric tables below (error correction per version, alignment pattern
// positions, precomputed format/version bits, GF(256) tables) are values from
// ISO/IEC 18004, extracted mechanically from a reference library (never
// retyped by hand, to rule out a typo in a Reed-Solomon table) and then
// verified matrix by matrix against that library (same mask and EC level
// forced) on ~400 inputs (lengths 0-1000, structured and random content,
// versions 1-20).
//
// The first verification round found FOUR real bugs, none visible by reading
// the code: the order between reserving the format area and drawing the
// timing pattern; an indexing error translating Python's `matrix[-i][8]`
// (where `a[-0] == a[0]`); mutating the `for` control variable during module
// placement, which in JS affects the next decrement (unlike Python's
// precomputed `range`); and byte-alignment padding, which must ALWAYS be
// applied, even when data is already aligned. Each alone would have produced
// a QR code that looks valid and does not scan. Module placement
// (`qrPlaceModules`) follows the zigzag algorithm of the specification
// (§7.7.3).
//
// QR_ECC_M[version] = [[n_blocks, total_codewords_per_block, data_codewords_per_block], ...]
// (one or two entries: some versions have blocks of two different sizes)
const QR_ECC_M = {
  1: [[1, 26, 16]],
  2: [[1, 44, 28]],
  3: [[1, 70, 44]],
  4: [[2, 50, 32]],
  5: [[2, 67, 43]],
  6: [[4, 43, 27]],
  7: [[4, 49, 31]],
  8: [[2, 60, 38], [2, 61, 39]],
  9: [[3, 58, 36], [2, 59, 37]],
  10: [[4, 69, 43], [1, 70, 44]],
  11: [[1, 80, 50], [4, 81, 51]],
  12: [[6, 58, 36], [2, 59, 37]],
  13: [[8, 59, 37], [1, 60, 38]],
  14: [[4, 64, 40], [5, 65, 41]],
  15: [[5, 65, 41], [5, 66, 42]],
  16: [[7, 73, 45], [3, 74, 46]],
  17: [[10, 74, 46], [1, 75, 47]],
  18: [[9, 69, 43], [4, 70, 44]],
  19: [[3, 70, 44], [11, 71, 45]],
  20: [[3, 67, 41], [13, 68, 42]],
};

// Indexed by real VERSION (not version-2): version 1 is absent on purpose, it
// has no alignment patterns (checked against a reference library).
const QR_ALIGNMENT_POS = {
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
  11: [6, 30, 54],
  12: [6, 32, 58],
  13: [6, 34, 62],
  14: [6, 26, 46, 66],
  15: [6, 26, 48, 70],
  16: [6, 26, 50, 74],
  17: [6, 30, 54, 78],
  18: [6, 30, 56, 82],
  19: [6, 30, 58, 86],
  20: [6, 34, 62, 90],
};

// 32 values (index = ec_level<<3 | mask), with BCH(15,5) and the 0x5412 format
// mask already applied. For level M ec_level is 0, so with fixed mask 0 the
// index used is always 0.
const QR_FORMAT_INFO = [
  21522, 20773, 24188, 23371, 17913, 16590, 20375, 19104, 30660, 29427,
  32170, 30877, 26159, 25368, 27713, 26998, 5769, 5054, 7399, 6608, 1890,
  597, 3340, 2107, 13663, 12392, 16177, 14854, 9396, 8579, 11994, 11245,
];

// Index = version-7 (18 bits, BCH(18,6)), for versions 7-40.
const QR_VERSION_INFO = [
  31892, 34236, 39577, 42195, 48118, 51042, 55367, 58893, 63784, 68472,
  70749, 76311, 79154, 84390, 87683, 92361, 96236, 102084, 102881, 110507,
  110734, 117786, 119615, 126325, 127568, 133589, 136944, 141498, 145311,
  150283, 152622, 158308, 161089, 167017,
];

const QR_GALOIS_EXP = [1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76, 152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161, 95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206, 129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204, 133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168, 77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230, 209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227, 219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65, 130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166, 81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18, 36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44, 88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1];
const QR_GALOIS_LOG = [0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75, 4, 100, 224, 14, 52, 141, 239, 129, 28, 193, 105, 248, 200, 8, 76, 113, 5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218, 240, 18, 130, 69, 29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166, 6, 191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136, 54, 208, 148, 206, 143, 150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64, 30, 66, 182, 163, 195, 72, 126, 110, 107, 58, 40, 84, 250, 133, 186, 61, 202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243, 167, 87, 7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24, 227, 165, 153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46, 55, 63, 209, 91, 149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190, 97, 242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57, 83, 71, 109, 65, 162, 31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246, 108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90, 203, 89, 95, 176, 156, 169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215, 79, 174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80, 88, 175];

function qrGfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return QR_GALOIS_EXP[(QR_GALOIS_LOG[a] + QR_GALOIS_LOG[b]) % 255];
}

function qrRsGeneratorPoly(degree) {
  let g = [1];
  for (let i = 0; i < degree; i++) {
    const root = QR_GALOIS_EXP[i];
    const next = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) {
      next[j] ^= g[j];
      next[j + 1] ^= qrGfMul(g[j], root);
    }
    g = next;
  }
  return g;
}

function qrRsComputeEcc(dataBytes, eccLen) {
  const gen = qrRsGeneratorPoly(eccLen);
  const remainder = dataBytes.concat(new Array(eccLen).fill(0));
  for (let i = 0; i < dataBytes.length; i++) {
    const coef = remainder[i];
    if (coef === 0) continue;
    for (let j = 0; j < gen.length; j++) {
      remainder[i + j] ^= qrGfMul(gen[j], coef);
    }
  }
  return remainder.slice(dataBytes.length);
}

class QrBitBuffer {
  constructor() {
    this.bits = [];
  }
  push(value, length) {
    for (let i = length - 1; i >= 0; i--) {
      this.bits.push((value >>> i) & 1);
    }
  }
  get length() {
    return this.bits.length;
  }
}

function qrCharCountBits(version) {
  return version <= 9 ? 8 : 16; // byte mode
}

function qrDataCapacityBits(version) {
  const groups = QR_ECC_M[version];
  let totalData = 0;
  for (const [nBlocks, , nData] of groups) totalData += nBlocks * nData;
  return totalData * 8;
}

function qrPickVersion(byteLen) {
  for (let v = 1; v <= 20; v++) {
    const headerBits = 4 + qrCharCountBits(v);
    if (headerBits + byteLen * 8 <= qrDataCapacityBits(v)) return v;
  }
  throw new Error("testo troppo lungo per un QR code (livello M, fino a versione 20)");
}

function qrBuildDataCodewords(version, dataBytes) {
  const bb = new QrBitBuffer();
  bb.push(0b0100, 4); // mode indicator: byte
  bb.push(dataBytes.length, qrCharCountBits(version));
  for (const b of dataBytes) bb.push(b, 8);

  const capacityBits = qrDataCapacityBits(version);
  const termLen = Math.min(4, Math.max(0, capacityBits - bb.length));
  bb.push(0, termLen);
  // Byte alignment: ALWAYS `8 - (length mod 8)` bits, which is 8 (a whole
  // byte), not 0, when the data is already aligned. Verified against a
  // reference library: it is unconditional. Capped by the remaining capacity
  // so it never overflows when the terminator was already truncated for lack
  // of space.
  const padToByte = Math.min(8 - (bb.length % 8), capacityBits - bb.length);
  if (padToByte > 0) bb.push(0, padToByte);

  const padBytes = [0xec, 0x11];
  let p = 0;
  while (bb.length < capacityBits) {
    bb.push(padBytes[p % 2], 8);
    p++;
  }

  const bytes = [];
  for (let i = 0; i < bb.length; i += 8) {
    let byte = 0;
    for (let k = 0; k < 8; k++) byte = (byte << 1) | bb.bits[i + k];
    bytes.push(byte);
  }
  return bytes;
}

// Splits into blocks, computes the ECC for each, interleaves data then ECC
// (ISO/IEC 18004 §7.5), and appends the final remainder bits (§7.6), needed
// only for versions where the available modules are not a multiple of 8.
function qrBuildFinalBits(version, dataCodewords) {
  const groups = QR_ECC_M[version];
  const eccLen = groups[0][1] - groups[0][2];

  const dataBlocks = [];
  const eccBlocks = [];
  let offset = 0;
  for (const [nBlocks, , nData] of groups) {
    for (let b = 0; b < nBlocks; b++) {
      const block = dataCodewords.slice(offset, offset + nData);
      offset += nData;
      dataBlocks.push(block);
      eccBlocks.push(qrRsComputeEcc(block, eccLen));
    }
  }

  const maxDataLen = Math.max(...dataBlocks.map((b) => b.length));
  const codewords = [];
  for (let col = 0; col < maxDataLen; col++) {
    for (const block of dataBlocks) {
      if (col < block.length) codewords.push(block[col]);
    }
  }
  for (let col = 0; col < eccLen; col++) {
    for (const block of eccBlocks) {
      codewords.push(block[col]);
    }
  }

  const bits = [];
  for (const cw of codewords) {
    for (let i = 7; i >= 0; i--) bits.push((cw >>> i) & 1);
  }

  const remainderTable = {
    2: 7, 3: 7, 4: 7, 5: 7, 6: 7,
    14: 3, 15: 3, 16: 3, 17: 3, 18: 3, 19: 3, 20: 3,
    21: 4, 22: 4, 23: 4, 24: 4, 25: 4, 26: 4, 27: 4,
  };
  const remainder = remainderTable[version] || 0;
  for (let i = 0; i < remainder; i++) bits.push(0);
  return bits;
}

// Builds the empty matrix with the fixed patterns (finders, separators,
// timing, alignment) in place, plus a parallel `isData` array marking which
// cells remain free for data: needed later to know which cells to mask (the
// dark module and the format/version areas are never masked).
function qrBuildBaseMatrix(version) {
  const size = version * 4 + 17;
  const m = [];
  for (let i = 0; i < size; i++) m.push(new Array(size).fill(2)); // 2 = free

  // ORDER (verified against a reference library): reserve the format/version
  // area BEFORE the timing pattern, not after. The timing pattern crosses the
  // intersections (row 6, column 8) and (row 8, column 6): reserving
  // afterwards would erase the timing bit already written there.
  // Note: the reference indexes `matrix[-i][8]` with `i` starting at 0, and in
  // Python `a[-0]` IS `a[0]`, so the real mirror starts at i=1, at index
  // `size-i`, not `size-1-i`.
  for (let i = 0; i < 9; i++) {
    m[i][8] = 0;
    m[8][i] = 0;
  }
  for (let i = 1; i < 9; i++) {
    m[size - i][8] = 0;
    m[8][size - i] = 0;
  }
  if (version >= 7) {
    for (let i = 0; i < 6; i++) {
      m[size - 11][i] = 0;
      m[size - 10][i] = 0;
      m[size - 9][i] = 0;
      m[i][size - 11] = 0;
      m[i][size - 10] = 0;
      m[i][size - 9] = 0;
    }
  }

  // Timing pattern: rows/columns 6, alternating, starting dark at position 8
  // (after the finder patterns and separators). It writes OVER the reservation
  // just made where it crosses the format strip.
  for (let i = 8; i < size - 8; i++) {
    const bit = i % 2 === 0 ? 1 : 0;
    m[6][i] = bit;
    m[i][6] = bit;
  }

  // 7x7 finder pattern + separator, in three corners (not bottom right).
  const finderPattern = [
    [1, 1, 1, 1, 1, 1, 1],
    [1, 0, 0, 0, 0, 0, 1],
    [1, 0, 1, 1, 1, 0, 1],
    [1, 0, 1, 1, 1, 0, 1],
    [1, 0, 1, 1, 1, 0, 1],
    [1, 0, 0, 0, 0, 0, 1],
    [1, 1, 1, 1, 1, 1, 1],
  ];
  function placeFinder(topRow, topCol) {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const rr = topRow + r;
        const cc = topCol + c;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        if (r >= 0 && r <= 6 && c >= 0 && c <= 6) {
          m[rr][cc] = finderPattern[r][c];
        } else {
          m[rr][cc] = 0; // separator, always light
        }
      }
    }
  }
  placeFinder(0, 0);
  placeFinder(0, size - 7);
  placeFinder(size - 7, 0);

  // Alignment patterns (absent in version 1).
  const positions = QR_ALIGNMENT_POS[version];
  if (positions) {
    const alignPattern = [
      [1, 1, 1, 1, 1],
      [1, 0, 0, 0, 1],
      [1, 0, 1, 0, 1],
      [1, 0, 0, 0, 1],
      [1, 1, 1, 1, 1],
    ];
    const minPos = positions[0];
    const maxPos = positions[positions.length - 1];
    const finderCorners = new Set([`${minPos},${minPos}`, `${minPos},${maxPos}`, `${maxPos},${minPos}`]);
    for (const x of positions) {
      for (const y of positions) {
        if (finderCorners.has(`${x},${y}`)) continue;
        const i0 = x - 2;
        const j0 = y - 2;
        for (let r = 0; r < 5; r++) {
          for (let c = 0; c < 5; c++) {
            m[i0 + r][j0 + c] = alignPattern[r][c];
          }
        }
      }
    }
  }

  // The dark module (m[size-8][8]) is NOT written here: it coincides with the
  // last cell touched by the loop in `qrWriteFormatInfo` (i=7, its mirror
  // `size-1-i`), and in the reference whoever writes LAST wins, i.e. the dark
  // module. Writing it here would be silently overwritten later. It is still
  // outside the data area: the generic reservation above already excludes it.

  const isData = m.map((row) => row.map((v) => v === 2));
  return { m, isData, size };
}

// Places data/ECC bits in the matrix along the zigzag path of ISO/IEC 18004
// §7.7.3: two-module-wide columns, right to left, alternating up and down,
// skipping the timing pattern column.
function qrPlaceModules(m, isData, size, bits) {
  let idx = 0;
  // `rightBase` is purely the loop control (decremented by 2 each time). The
  // "skip the timing column" adjustment lives in `right`, a SEPARATE variable:
  // mutating a `for` control variable inside its body affects the next
  // decrement in JS (unlike Python's precomputed `range()`).
  for (let rightBase = size - 1; rightBase > 0; rightBase -= 2) {
    let right = rightBase;
    if (right <= 6) right -= 1;
    for (let vertical = 0; vertical < size; vertical++) {
      for (let z = 0; z < 2; z++) {
        const col = right - z;
        let upwards = (right & 2) === 0;
        if (col < 6) upwards = !upwards;
        const row = upwards ? size - 1 - vertical : vertical;
        if (isData[row][col] && idx < bits.length) {
          m[row][col] = bits[idx];
          idx++;
        }
      }
    }
  }
}

function qrApplyMask(m, isData, size) {
  for (let i = 0; i < size; i++) {
    for (let j = 0; j < size; j++) {
      if (isData[i][j] && (i + j) % 2 === 0) {
        m[i][j] ^= 1;
      }
    }
  }
}

function qrWriteFormatInfo(m, size) {
  // Level M, mask 0: fmt = (0 << 3) | 0 = 0.
  const formatInfo = QR_FORMAT_INFO[0];
  let voffset = 0;
  let hoffset = 0;
  for (let i = 0; i < 8; i++) {
    const vbit = (formatInfo >>> i) & 1;
    const hbit = (formatInfo >>> (14 - i)) & 1;
    if (i === 6) {
      voffset = 1;
      hoffset = 1;
    }
    m[i + voffset][8] = vbit;
    m[8][i + hoffset] = hbit;
    m[8][size - 1 - i] = vbit;
    m[size - 1 - i][8] = hbit;
  }
  // Written AFTER the loop on purpose: it coincides with the last cell the loop
  // just touched (i=7), and here the dark module must win.
  m[size - 8][8] = 1;
}

function qrWriteVersionInfo(m, size, version) {
  if (version < 7) return;
  const versionInfo = QR_VERSION_INFO[version - 7];
  for (let i = 0; i < 6; i++) {
    const bit1 = (versionInfo >>> (i * 3)) & 1;
    const bit2 = (versionInfo >>> (i * 3 + 1)) & 1;
    const bit3 = (versionInfo >>> (i * 3 + 2)) & 1;
    m[size - 11][i] = bit1;
    m[size - 10][i] = bit2;
    m[size - 9][i] = bit3;
    m[i][size - 11] = bit1;
    m[i][size - 10] = bit2;
    m[i][size - 9] = bit3;
  }
}

/** Encodes `text` (UTF-8) as a QR code. Returns `{ version, size, matrix }`
 * where `matrix` is an array of arrays of 0/1 (1 = dark module). Byte mode
 * only, level M, fixed mask 0; see the comment at the top of this section. */
function qrEncodeText(text) {
  const dataBytes = Array.from(utf8Encode(text));
  const version = qrPickVersion(dataBytes.length);
  const dataCodewords = qrBuildDataCodewords(version, dataBytes);
  const bits = qrBuildFinalBits(version, dataCodewords);
  const { m, isData, size } = qrBuildBaseMatrix(version);
  qrPlaceModules(m, isData, size, bits);
  qrApplyMask(m, isData, size);
  qrWriteFormatInfo(m, size);
  qrWriteVersionInfo(m, size, version);
  return { version, size, matrix: m };
}

// -----------------------------------------------------------------------
// Binary reader/writer: same role as `Reader`/`Writer` in src/codec.rs. The
// layout MUST stay identical on both sides: if one changes, so does the
// other, in the same commit.
// -----------------------------------------------------------------------

class ByteReader {
  constructor(buf) {
    this.buf = buf;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    this.pos = 0;
  }
  u8() {
    const v = this.buf[this.pos];
    this.pos += 1;
    return v;
  }
  u16() {
    const v = this.view.getUint16(this.pos, true);
    this.pos += 2;
    return v;
  }
  u32() {
    const v = this.view.getUint32(this.pos, true);
    this.pos += 4;
    return v;
  }
  i64() {
    const v = this.view.getBigInt64(this.pos, true);
    this.pos += 8;
    return Number(v);
  }
  key32() {
    return this.bytes(32);
  }
  bytes(n) {
    const v = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return v;
  }
  strU16() {
    const len = this.u16();
    return utf8Decode(this.bytes(len));
  }
}

class ByteWriter {
  constructor() {
    this.parts = [];
  }
  u8(v) {
    this.parts.push(new Uint8Array([v & 0xff]));
    return this;
  }
  u16(v) {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v, true);
    this.parts.push(b);
    return this;
  }
  u32(v) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v, true);
    this.parts.push(b);
    return this;
  }
  i64(v) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigInt64(0, BigInt(v), true);
    this.parts.push(b);
    return this;
  }
  bytes(b) {
    this.parts.push(b);
    return this;
  }
  strU16(s) {
    const enc = utf8Encode(s);
    this.u16(enc.length);
    this.parts.push(enc);
    return this;
  }
  toBytes() {
    return concatBytes(this.parts);
  }
}

// -----------------------------------------------------------------------
// Encoding of persisted records: mirrors exactly
// src/codec.rs::{encode,decode}_{peer,prekey}_record.
// -----------------------------------------------------------------------

function encodePeerRecordJs(rec) {
  const w = new ByteWriter();
  w.bytes(rec.public).i64(rec.first_seen_unix).u8(rec.verified ? 1 : 0);
  if (rec.label) {
    w.strU16(rec.label);
  } else {
    w.u16(0);
  }
  return w.toBytes();
}

function decodePeerRecordJs(buf) {
  const r = new ByteReader(buf);
  const public_ = r.key32();
  const first_seen_unix = r.i64();
  const verified = r.u8() !== 0;
  const label = r.strU16();
  return { public: public_, first_seen_unix, verified, label: label === "" ? null : label };
}

function encodePrekeyRecordJs(rec) {
  const w = new ByteWriter();
  w.bytes(rec.peer);
  if (rec.sua_prekey) {
    w.u8(1).bytes(rec.sua_prekey);
  } else {
    w.u8(0);
  }
  const mie = rec.mie || [];
  w.u8(mie.length);
  for (const k of mie) w.bytes(k);
  if (rec.mia_epoca) {
    w.u8(1).bytes(rec.mia_epoca);
  } else {
    w.u8(0);
  }
  if (rec.sua_epoca) {
    w.u8(1).bytes(rec.sua_epoca);
  } else {
    w.u8(0);
  }
  w.i64(rec.visto_a).i64(rec.rogo_a);
  return w.toBytes();
}

function decodePrekeyRecordJs(buf) {
  const r = new ByteReader(buf);
  const peer = r.key32();
  const sua_prekey = r.u8() === 1 ? r.key32() : null;
  const count = r.u8();
  const mie = [];
  for (let i = 0; i < count; i++) mie.push(r.key32());
  const mia_epoca = r.u8() === 1 ? r.key32() : null;
  const sua_epoca = r.u8() === 1 ? r.key32() : null;
  const visto_a = r.i64();
  const rogo_a = r.i64();
  return { peer, sua_prekey, mie, mia_epoca, sua_epoca, visto_a, rogo_a };
}

// `IncomingItem` tags: mirror src/codec.rs::TAG_*.
const TAG_MESSAGE = 0;
const TAG_OWN_MESSAGE = 1;
const TAG_BURNED = 2;
const TAG_OWN_IDENTITY_CARD = 3;
const TAG_IDENTITY_CARD = 4;

function decodeIncomingItem(buf) {
  const r = new ByteReader(buf);
  const tag = r.u8();
  switch (tag) {
    case TAG_MESSAGE: {
      const sender = r.key32();
      const statusTag = r.u8();
      let senderStatus;
      if (statusTag === 0) {
        senderStatus = { kind: "new" };
      } else {
        const verified = r.u8() !== 0;
        const label = r.strU16();
        senderStatus = { kind: "known", verified, label: label === "" ? null : label };
      }
      const gruppo = r.u8() !== 0;
      const destinatari = r.u32();
      const sentAtUnix = r.i64();
      const plaintextLen = r.u32();
      const text = utf8Decode(r.bytes(plaintextLen));
      return { tag: "message", sender, senderStatus, gruppo, destinatari, sentAtUnix, text };
    }
    case TAG_OWN_MESSAGE: {
      const recipient = r.key32();
      const label = r.strU16();
      const sentAtUnix = r.i64();
      const plaintextLen = r.u32();
      const text = utf8Decode(r.bytes(plaintextLen));
      return {
        tag: "ownMessage",
        recipient,
        recipientLabel: label === "" ? null : label,
        sentAtUnix,
        text,
      };
    }
    case TAG_BURNED: {
      const peer = r.key32();
      const sentAtUnix = r.i64();
      return { tag: "burned", peer, sentAtUnix };
    }
    case TAG_OWN_IDENTITY_CARD: {
      const fingerprint = r.strU16();
      return { tag: "ownIdentityCard", fingerprint };
    }
    case TAG_IDENTITY_CARD: {
      const peer = r.key32();
      const fingerprint = r.strU16();
      const outcome = r.u8() === 0 ? "pinned" : "alreadyPinned";
      return { tag: "identityCard", peer, fingerprint, outcome };
    }
    default:
      throw new Error("tag IncomingItem sconosciuto: " + tag);
  }
}

function decodeLabelOutcome(buf) {
  const r = new ByteReader(buf);
  const tag = r.u8();
  if (tag === 0) return { kind: "assigned" };
  const existing = r.key32();
  const existingFingerprint = r.strU16();
  const incomingFingerprint = r.strU16();
  return { kind: "conflict", existing, existingFingerprint, incomingFingerprint };
}

// Mirrors exactly src/codec.rs::encode_incoming_file.
function decodeIncomingFile(buf) {
  const r = new ByteReader(buf);
  const sender = r.key32();
  const statusTag = r.u8();
  let senderStatus;
  if (statusTag === 0) {
    senderStatus = { kind: "new" };
  } else {
    const verified = r.u8() !== 0;
    const label = r.strU16();
    senderStatus = { kind: "known", verified, label: label === "" ? null : label };
  }
  const nostro = r.u8() !== 0;
  const name = r.strU16();
  const mime = r.strU16();
  const sentAtUnix = r.i64();
  const contentLen = r.u32();
  const content = r.bytes(contentLen);
  return { sender, senderStatus, nostro, name, mime, sentAtUnix, content };
}

// -----------------------------------------------------------------------
// Bridge to the wasm module: same protocol as src/marshal.rs.
// -----------------------------------------------------------------------

const ERROR_MESSAGES = {
  1: "formato non valido",
  2: "versione non supportata da questa app: aggiornala",
  3: "questo testo non è cifrato con MusyBoard",
  4: "decodifica fallita: il testo è corrotto o incompleto",
  5: "decifratura fallita: chiave sbagliata o testo manomesso",
  6: "nessun destinatario selezionato: scegli un contatto prima di cifrare",
  7: "livello di cifratura non supportato da questa versione dell'app",
  8: "questo messaggio l'hai scritto tu: può aprirlo solo il destinatario",
  9: "errore interno del portachiavi",
  10: "l'hai scritto tu, e la chiave verso cui era cifrato non c'è più: non si riapre",
  90: "generatore casuale non pronto (bug interno)",
  92: "nessuna identità caricata: aprila prima da MusyBoard",
  93: "testo non valido",
  94: "dati malformati (bug interno)",
};

class MusyBoardError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] || "errore sconosciuto (codice " + code + ")");
    this.code = code;
  }
}

let wasm = null;

async function loadWasmModule() {
  if (wasm) return;
  ensurePaths();
  if (!files.fileExists(WASM_PATH)) {
    throw new Error(
      "musyboard_wasm.wasm non trovato in " +
        WASM_PATH +
        " — copialo nella cartella LOCALE di Scriptable (non iCloud) prima di continuare."
    );
  }
  const data = files.read(WASM_PATH);
  const bytes = new Uint8Array(data.getBytes());
  const { instance } = await WebAssembly.instantiate(bytes, {});
  wasm = instance;
}

function memBuffer() {
  // Re-read on every use, never cached: if wasm memory grows (`memory.grow`),
  // the previous `ArrayBuffer` is detached and unusable;
  // `instance.exports.memory.buffer` after growth is a NEW object.
  return new Uint8Array(wasm.exports.memory.buffer);
}

function writeBytes(bytes) {
  const ptr = wasm.exports.mb_alloc(bytes.length);
  memBuffer().set(bytes, ptr);
  return { ptr, len: bytes.length };
}

function writeStr(str) {
  return writeBytes(utf8Encode(str));
}

function readMemory(ptr, len) {
  return memBuffer().slice(ptr, ptr + len);
}

function unpackU64(bigResult) {
  const ptr = Number(bigResult >> 32n) >>> 0;
  const len = Number(bigResult & 0xffffffffn) >>> 0;
  return { ptr, len };
}

/** Calls a function returning a packed `u64` and returns the result bytes, or
 * throws `MusyBoardError` on an error outcome. */
function callProducing(fn, ...args) {
  const packed = fn(...args);
  const { ptr, len } = unpackU64(packed);
  if (ptr === 0) {
    throw new MusyBoardError(len);
  }
  const bytes = readMemory(ptr, len);
  wasm.exports.mb_dealloc(ptr, len);
  return bytes;
}

/** Like `callProducing`, but `(ptr=0, len=0)` means "no data" and returns
 * `null` instead of throwing, for functions like `mb_current_peer` where
 * absence is not an error. `(ptr=0, len>0)` is still a real error. */
function callProducingOptional(fn, ...args) {
  const packed = fn(...args);
  const { ptr, len } = unpackU64(packed);
  if (ptr === 0 && len === 0) return null;
  if (ptr === 0) {
    throw new MusyBoardError(len);
  }
  const bytes = readMemory(ptr, len);
  wasm.exports.mb_dealloc(ptr, len);
  return bytes;
}

/** Calls a function returning only a `u32` code (0 = success). */
function callStatus(fn, ...args) {
  const code = fn(...args);
  if (code !== 0) {
    throw new MusyBoardError(code);
  }
}

function nowUnixBig() {
  return BigInt(Math.floor(Date.now() / 1000));
}

// -----------------------------------------------------------------------
// Entropy: bridge through a hidden WebView (~1-2 ms per 32 bytes). Must be
// called before EVERY operation that consumes randomness on the Rust side:
// `mb_seed_rng` discards the seed after one use on purpose, so it is never
// reused for two different keys in the same run.
// -----------------------------------------------------------------------

// The last seed consumed, to notice if the same one arrives twice. Lives for
// the run only: not persisted, not a secret to keep.
let ultimoSeme = null;

async function freshEntropy32() {
  const wv = new WebView();
  await wv.loadHTML("<html></html>");
  const json = await wv.evaluateJavaScript(
    "JSON.stringify(Array.from(crypto.getRandomValues(new Uint8Array(32))))",
    false
  );
  const bytes = new Uint8Array(JSON.parse(json));
  controllaSeme(bytes);
  ultimoSeme = bytes;
  return bytes;
}

/**
 * The three checks on the seed. Throws if it is bad, returns nothing.
 *
 * A separate, **synchronous** function on purpose, so it can run in any JS
 * engine, without a WebView and without iOS.
 *
 * ## Why they exist
 *
 * This bridge is the only part of the system that depends on WKWebView
 * behaviour, and it has been verified on a real device only briefly. If it
 * ever broke, it would break silently: a seed would still arrive, the
 * operation would succeed, and messages would be badly encrypted with nothing
 * saying so.
 *
 * The worst way to break is also the most mundane: a WebView returning a value
 * **already seen**, from a cache or an unevaluated response. The seed is
 * discarded after one use on purpose, so two operations with the same seed
 * mean the same ephemeral key and the same nonce, i.e. keystream reuse, the
 * one thing the core must never allow.
 *
 * Better to stop with a readable error than encrypt with fake entropy.
 */
function controllaSeme(bytes) {
  if (bytes.length !== 32) {
    throw new Error(
      "Entropia: ricevuti " + bytes.length + " byte invece di 32. " +
      "Il ponte con la WebView non funziona: non si cifra."
    );
  }
  if (bytes.every((b) => b === bytes[0])) {
    throw new Error(
      "Entropia: 32 byte tutti uguali. Non e' caso, e' un ponte rotto: non si cifra."
    );
  }
  if (ultimoSeme !== null && bytes.every((b, i) => b === ultimoSeme[i])) {
    throw new Error(
      "Entropia: lo stesso seme di prima. La WebView sta restituendo un valore " +
      "vecchio, e cifrare adesso riuserebbe chiave e nonce: non si cifra."
    );
  }
}

async function seedRng() {
  const entropy = await freshEntropy32();
  const { ptr, len } = writeBytes(entropy);
  callStatus(wasm.exports.mb_seed_rng, ptr, len);
  wasm.exports.mb_dealloc(ptr, len);
}

// -----------------------------------------------------------------------
// Session state (in memory, for the duration of THIS run).
// -----------------------------------------------------------------------

let identityLoaded = false;
let currentSecret = null;
let currentPublic = null;
let currentSettings = { app_package_constant: "ios-scriptable", effimero_default: false };

function loadConfigFile() {
  ensurePaths();
  // `.new` exists only after the new state has been fully written and read
  // back: after a crash before the move it is therefore the most recent.
  // `.bak` covers a crash after moving the old file but before installing the
  // new one.
  for (const path of [CONFIG_TMP_PATH, CONFIG_PATH, CONFIG_BACKUP_PATH]) {
    if (!files.fileExists(path)) continue;
    try {
      return JSON.parse(files.readString(path));
    } catch (_) {
      // A partial file is never chosen: fall back to the previous generation.
    }
  }
  return null;
}

function saveConfigFile(state) {
  ensurePaths();
  const serialized = JSON.stringify(state, null, 2);

  // Step 1: the new state is written and verified separately. If Scriptable
  // is killed here, `loadConfigFile` recovers `.new`.
  if (files.fileExists(CONFIG_TMP_PATH)) files.remove(CONFIG_TMP_PATH);
  files.writeString(CONFIG_TMP_PATH, serialized);
  JSON.parse(files.readString(CONFIG_TMP_PATH));

  // Step 2: keep a valid generation until the new one is active. Scriptable
  // exposes `move` but no atomic replace; the `.new`/`.bak` journal makes both
  // windows recoverable.
  if (files.fileExists(CONFIG_BACKUP_PATH)) files.remove(CONFIG_BACKUP_PATH);
  if (files.fileExists(CONFIG_PATH)) files.move(CONFIG_PATH, CONFIG_BACKUP_PATH);
  files.move(CONFIG_TMP_PATH, CONFIG_PATH);
}

function stateContactToJson(rec) {
  return {
    public_b64: base64Encode(rec.public),
    label: rec.label,
    first_seen_unix: rec.first_seen_unix,
    verified: rec.verified,
  };
}

function jsonToStateContact(obj) {
  return {
    public: base64Decode(obj.public_b64),
    label: obj.label || null,
    first_seen_unix: obj.first_seen_unix,
    verified: !!obj.verified,
  };
}

function ratchetToJson(rec) {
  return {
    peer_public_b64: base64Encode(rec.peer),
    peer_prekey_b64: rec.sua_prekey ? base64Encode(rec.sua_prekey) : null,
    my_prekeys_b64: rec.mie.map(base64Encode),
    my_epoch_secret_b64: rec.mia_epoca ? base64Encode(rec.mia_epoca) : null,
    peer_epoch_public_b64: rec.sua_epoca ? base64Encode(rec.sua_epoca) : null,
    seen_at_unix: rec.visto_a,
    burned_at_unix: rec.rogo_a,
  };
}

function jsonToRatchet(obj) {
  return {
    peer: base64Decode(obj.peer_public_b64),
    sua_prekey: obj.peer_prekey_b64 ? base64Decode(obj.peer_prekey_b64) : null,
    mie: (obj.my_prekeys_b64 || []).map(base64Decode),
    mia_epoca: obj.my_epoch_secret_b64 ? base64Decode(obj.my_epoch_secret_b64) : null,
    sua_epoca: obj.peer_epoch_public_b64 ? base64Decode(obj.peer_epoch_public_b64) : null,
    visto_a: obj.seen_at_unix,
    rogo_a: obj.burned_at_unix,
  };
}

function hydrateFromConfig(config) {
  const secret = base64Decode(config.my_identity.secret_b64);
  const { ptr } = writeBytes(secret);
  callProducing(wasm.exports.mb_load_identity, ptr); // starts the "pending" state
  wasm.exports.mb_dealloc(ptr, 32);

  for (const c of config.contacts || []) {
    const bytes = encodePeerRecordJs(jsonToStateContact(c));
    const w = writeBytes(bytes);
    callStatus(wasm.exports.mb_restore_peer, w.ptr, w.len);
    wasm.exports.mb_dealloc(w.ptr, w.len);
  }
  for (const rs of config.ratchet_state || []) {
    const bytes = encodePrekeyRecordJs(jsonToRatchet(rs));
    const w = writeBytes(bytes);
    callStatus(wasm.exports.mb_restore_prekey_record, w.ptr, w.len);
    wasm.exports.mb_dealloc(w.ptr, w.len);
  }
  callStatus(wasm.exports.mb_finish_load);
}

function dumpToConfig() {
  const peersCount = wasm.exports.mb_dump_peers_count();
  const contacts = [];
  for (let i = 0; i < peersCount; i++) {
    const bytes = callProducing(wasm.exports.mb_dump_peer_at, i);
    contacts.push(stateContactToJson(decodePeerRecordJs(bytes)));
  }
  const prekeyCount = wasm.exports.mb_dump_prekey_count();
  const ratchet_state = [];
  for (let i = 0; i < prekeyCount; i++) {
    const bytes = callProducing(wasm.exports.mb_dump_prekey_at, i);
    ratchet_state.push(ratchetToJson(decodePrekeyRecordJs(bytes)));
  }
  return {
    schema_version: 1,
    my_identity: {
      secret_b64: base64Encode(currentSecret),
      public_b64: base64Encode(currentPublic),
    },
    contacts,
    ratchet_state,
    settings: currentSettings,
  };
}

function persistAll() {
  saveConfigFile(dumpToConfig());
}

async function bootstrap() {
  await loadWasmModule();
  const config = loadConfigFile();
  if (config && config.my_identity) {
    currentSecret = base64Decode(config.my_identity.secret_b64);
    currentPublic = base64Decode(config.my_identity.public_b64);
    currentSettings = config.settings || currentSettings;
    hydrateFromConfig(config);
    identityLoaded = true;
  }
}

// -----------------------------------------------------------------------
// High-level operations (wrappers around the wasm module's mb_* functions).
// -----------------------------------------------------------------------

async function generateIdentity() {
  await seedRng();
  const bytes = callProducing(wasm.exports.mb_generate_identity);
  return { secret: bytes.slice(0, 32), public: bytes.slice(32, 64) };
}

async function getIdentityCard() {
  await seedRng();
  const bytes = callProducing(wasm.exports.mb_identity_card);
  return utf8Decode(bytes);
}

function myFingerprint() {
  const bytes = callProducing(wasm.exports.mb_my_fingerprint);
  return utf8Decode(bytes);
}

function fingerprintOf(peerBytes) {
  const { ptr } = writeBytes(peerBytes);
  try {
    return utf8Decode(callProducing(wasm.exports.mb_fingerprint_of, ptr));
  } finally {
    wasm.exports.mb_dealloc(ptr, 32);
  }
}

function listContacts() {
  const count = wasm.exports.mb_dump_peers_count();
  const out = [];
  for (let i = 0; i < count; i++) {
    out.push(decodePeerRecordJs(callProducing(wasm.exports.mb_dump_peer_at, i)));
  }
  return out;
}

function setCurrentPeer(peerBytes) {
  const { ptr } = writeBytes(peerBytes);
  try {
    callStatus(wasm.exports.mb_set_current_peer, ptr);
  } finally {
    wasm.exports.mb_dealloc(ptr, 32);
  }
}

/** Public key bytes of the current recipient, or `null` if none is set. */
function getCurrentPeer() {
  return callProducingOptional(wasm.exports.mb_current_peer);
}

async function encryptText(text) {
  await seedRng();
  const { ptr, len } = writeStr(text);
  try {
    return utf8Decode(callProducing(wasm.exports.mb_encrypt, ptr, len, nowUnixBig()));
  } finally {
    wasm.exports.mb_dealloc(ptr, len);
  }
}

function decryptText(text) {
  const { ptr, len } = writeStr(text);
  try {
    return decodeIncomingItem(callProducing(wasm.exports.mb_decrypt, ptr, len, nowUnixBig()));
  } finally {
    wasm.exports.mb_dealloc(ptr, len);
  }
}

async function burnConversation(peerBytes) {
  await seedRng();
  const { ptr } = writeBytes(peerBytes);
  try {
    return utf8Decode(
      callProducing(wasm.exports.mb_burn_conversation, ptr, nowUnixBig())
    );
  } finally {
    wasm.exports.mb_dealloc(ptr, 32);
  }
}

function assignLabel(peerBytes, label) {
  const p = writeBytes(peerBytes);
  const l = writeStr(label);
  try {
    return decodeLabelOutcome(
      callProducing(wasm.exports.mb_assign_label, p.ptr, l.ptr, l.len)
    );
  } finally {
    wasm.exports.mb_dealloc(p.ptr, 32);
    wasm.exports.mb_dealloc(l.ptr, l.len);
  }
}

function confirmKeyChange(oldBytes, newBytes) {
  const o = writeBytes(oldBytes);
  const n = writeBytes(newBytes);
  try {
    callStatus(wasm.exports.mb_confirm_key_change, o.ptr, n.ptr, nowUnixBig());
  } finally {
    wasm.exports.mb_dealloc(o.ptr, 32);
    wasm.exports.mb_dealloc(n.ptr, 32);
  }
}

function forgetPeer(peerBytes) {
  const { ptr } = writeBytes(peerBytes);
  try {
    callStatus(wasm.exports.mb_forget_peer, ptr);
  } finally {
    wasm.exports.mb_dealloc(ptr, 32);
  }
}

function markVerified(peerBytes) {
  const { ptr } = writeBytes(peerBytes);
  try {
    callStatus(wasm.exports.mb_mark_verified, ptr);
  } finally {
    wasm.exports.mb_dealloc(ptr, 32);
  }
}

// -----------------------------------------------------------------------
// Attachments (photos, audio, any file). Unlike text messages (encrypted with
// an epoch, without forward secrecy, by choice), attachments ALWAYS use the
// forward secrecy chain on the Rust side, as the core recommends.
// -----------------------------------------------------------------------

function guessMimeType(filename) {
  const ext = (filename.split(".").pop() || "").toLowerCase();
  const table = {
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    png: "image/png",
    gif: "image/gif",
    heic: "image/heic",
    mp3: "audio/mpeg",
    m4a: "audio/mp4",
    wav: "audio/wav",
    mp4: "video/mp4",
    mov: "video/quicktime",
    pdf: "application/pdf",
    txt: "text/plain",
  };
  return table[ext] || "application/octet-stream";
}

// The name comes from inside the ciphertext, which makes it authentic, not
// safe as a path component: even a legitimate contact can send
// "../../config.json". Keep only the last component, strip characters with
// special meaning on common filesystems, and cap the length in UTF-8 bytes
// (not JS code units) to stay under normal file name limits with emoji or
// non-Latin scripts.
function safeAttachmentName(name) {
  const components = String(name || "").replace(/\\/g, "/").split("/");
  let candidate = components[components.length - 1] || "";
  candidate = candidate
    .replace(/[\u0000-\u001f\u007f/:]/g, "_")
    .replace(/^\.+/, "")
    .trim();
  if (!candidate) candidate = "allegato";

  let safe = "";
  let byteLength = 0;
  for (const character of candidate) {
    const characterLength = utf8Encode(character).length;
    if (byteLength + characterLength > 180) break;
    safe += character;
    byteLength += characterLength;
  }
  return safe || "allegato";
}

function bytesToScriptableData(bytes) {
  return Data.fromBase64String(base64Encode(bytes));
}

async function encryptFileFor(peerBytes, name, mime, contentBytes) {
  await seedRng();
  const p = writeBytes(peerBytes);
  const n = writeStr(name);
  const m = writeStr(mime);
  const c = writeBytes(contentBytes);
  try {
    return callProducing(
      wasm.exports.mb_encrypt_file,
      p.ptr,
      n.ptr,
      n.len,
      m.ptr,
      m.len,
      c.ptr,
      c.len,
      nowUnixBig()
    );
  } finally {
    wasm.exports.mb_dealloc(p.ptr, 32);
    wasm.exports.mb_dealloc(n.ptr, n.len);
    wasm.exports.mb_dealloc(m.ptr, m.len);
    wasm.exports.mb_dealloc(c.ptr, c.len);
  }
}

function decryptFileBytes(fileBytes) {
  const { ptr, len } = writeBytes(fileBytes);
  try {
    return decodeIncomingFile(callProducing(wasm.exports.mb_decrypt_file, ptr, len, nowUnixBig()));
  } finally {
    wasm.exports.mb_dealloc(ptr, len);
  }
}

// -----------------------------------------------------------------------
// Group messages (decision K). Only encryption needs a wrapper: an incoming
// group is recognised by `decryptText` (the same `mb_decrypt`; the core
// detects it from the blob) and arrives with `tag: "message"` and
// `gruppo: true`. No forward secrecy (K1), and the UI must NEVER show an
// author for a group message (K6); see `intestazioneMittente`.
// -----------------------------------------------------------------------

/** `peerPublicKeys` is an array of `Uint8Array(32)`. */
async function encryptGroup(peerPublicKeys, text) {
  await seedRng();
  const concatenated = concatBytes(peerPublicKeys);
  const peers = writeBytes(concatenated);
  const t = writeStr(text);
  try {
    const blob = callProducing(
      wasm.exports.mb_encrypt_group,
      peers.ptr,
      peerPublicKeys.length,
      t.ptr,
      t.len,
      nowUnixBig()
    );
    return utf8Decode(blob);
  } finally {
    wasm.exports.mb_dealloc(peers.ptr, concatenated.length);
    wasm.exports.mb_dealloc(t.ptr, t.len);
  }
}

// -----------------------------------------------------------------------
// Passphrase-encrypted backup (Argon2id). The keyring is opaque bytes for
// `backup::export`/`import` on the Rust side; the layout is chosen here,
// reusing the config.json encoders instead of inventing a second one:
// u32(count) + per record [u32(length) + bytes], contacts first, then
// chain/epoch state.
// -----------------------------------------------------------------------

function buildKeyringBlob() {
  const w = new ByteWriter();
  const peers = listContacts();
  w.u32(peers.length);
  for (const p of peers) {
    const bytes = encodePeerRecordJs(p);
    w.u32(bytes.length).bytes(bytes);
  }
  const prekeyCount = wasm.exports.mb_dump_prekey_count();
  w.u32(prekeyCount);
  for (let i = 0; i < prekeyCount; i++) {
    const bytes = callProducing(wasm.exports.mb_dump_prekey_at, i);
    w.u32(bytes.length).bytes(bytes);
  }
  return w.toBytes();
}

function parseKeyringBlob(buf) {
  const r = new ByteReader(buf);
  const peersCount = r.u32();
  const peers = [];
  for (let i = 0; i < peersCount; i++) {
    const len = r.u32();
    peers.push(decodePeerRecordJs(r.bytes(len)));
  }
  const prekeyCount = r.u32();
  const prekeys = [];
  for (let i = 0; i < prekeyCount; i++) {
    const len = r.u32();
    prekeys.push(decodePrekeyRecordJs(r.bytes(len)));
  }
  return { peers, prekeys };
}

/** Encrypts identity + keyring with a passphrase. Returns the blob in base64
 * (text, easy to copy or save; the real blob is binary). */
async function exportBackup(passphrase) {
  await seedRng();
  const p = writeStr(passphrase);
  const k = writeBytes(buildKeyringBlob());
  try {
    const blob = callProducing(wasm.exports.mb_export_backup, p.ptr, p.len, k.ptr, k.len);
    return base64Encode(blob);
  } finally {
    wasm.exports.mb_dealloc(p.ptr, p.len);
    wasm.exports.mb_dealloc(k.ptr, k.len);
  }
}

/** Opens a backup (base64) and installs the resulting session, like
 * `hydrateFromConfig` but from a backup instead of config.json. Overwrites the
 * current identity and contacts: the caller must already have warned the
 * user. */
function importBackupAndInstall(passphrase, base64Blob) {
  const blobBytes = base64Decode(base64Blob);
  const p = writeStr(passphrase);
  const b = writeBytes(blobBytes);
  let opened;
  try {
    opened = callProducing(wasm.exports.mb_import_backup, p.ptr, p.len, b.ptr, b.len);
  } finally {
    wasm.exports.mb_dealloc(p.ptr, p.len);
    wasm.exports.mb_dealloc(b.ptr, b.len);
  }
  const secret = opened.slice(0, 32);
  const keyringBytes = opened.slice(32);
  const { peers, prekeys } = parseKeyringBlob(keyringBytes);

  const s = writeBytes(secret);
  callProducing(wasm.exports.mb_load_identity, s.ptr);
  wasm.exports.mb_dealloc(s.ptr, 32);
  for (const rec of peers) {
    const bytes = encodePeerRecordJs(rec);
    const w = writeBytes(bytes);
    callStatus(wasm.exports.mb_restore_peer, w.ptr, w.len);
    wasm.exports.mb_dealloc(w.ptr, w.len);
  }
  for (const rec of prekeys) {
    const bytes = encodePrekeyRecordJs(rec);
    const w = writeBytes(bytes);
    callStatus(wasm.exports.mb_restore_prekey_record, w.ptr, w.len);
    wasm.exports.mb_dealloc(w.ptr, w.len);
  }
  callStatus(wasm.exports.mb_finish_load);

  currentSecret = secret;
  currentPublic = callProducing(wasm.exports.mb_my_public);
  identityLoaded = true;
}

// -----------------------------------------------------------------------
// UI, Alert-based. No UITable: with few contacts, button Alerts are simpler to
// keep correct.
// -----------------------------------------------------------------------

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function showMessage(title, message) {
  const a = new Alert();
  a.title = title;
  a.message = message;
  a.addAction("Ok");
  await a.present();
}

async function showError(e) {
  await showMessage("Errore", e && e.message ? e.message : String(e));
}

/** Shows `text` as a full-screen QR code, via inline SVG in a WebView: no image
 * file to generate or save. Consistent with the Android side ("shown, not
 * scanned"): this QR is meant for SOMEONE ELSE's camera, never read by this
 * script. Scriptable has (and must have) no camera access here. */
async function showQrCode(text) {
  const { size, matrix } = qrEncodeText(text);
  const quiet = 4; // light margin around the code, required by the standard
  const total = size + quiet * 2;
  let rects = "";
  for (let i = 0; i < size; i++) {
    for (let j = 0; j < size; j++) {
      if (matrix[i][j]) {
        rects += `<rect x="${j + quiet}" y="${i + quiet}" width="1" height="1"/>`;
      }
    }
  }
  const html =
    `<html><body style="margin:0;background:#fff;display:flex;align-items:center;justify-content:center;height:100vh;">` +
    `<svg viewBox="0 0 ${total} ${total}" style="width:92vw;height:92vw;shape-rendering:crispEdges;" fill="#000">` +
    rects +
    `</svg></body></html>`;
  const wv = new WebView();
  await wv.loadHTML(html);
  await wv.present(true);
}

async function screenImportBackupFlow() {
  const a = new Alert();
  a.title = "Importa da backup";
  a.message = "Incolla qui il backup (testo in base64) e la passphrase con cui è stato creato.";
  a.addTextField("Backup (base64)", "");
  a.addSecureTextField("Passphrase");
  a.addAction("Importa");
  a.addCancelAction("Annulla");
  if ((await a.present()) !== 0) return false;
  const blob = a.textFieldValue(0);
  const pass = a.textFieldValue(1);
  if (!blob || !pass) return false;
  try {
    importBackupAndInstall(pass, blob);
    persistAll();
    await showMessage("Fatto", "Identità e contatti ripristinati dal backup.");
    return true;
  } catch (e) {
    await showError(e);
    return false;
  }
}

async function screenExportBackupFlow() {
  const a = new Alert();
  a.title = "Esporta backup cifrato";
  a.message =
    "Il backup contiene la tua identità e i tuoi contatti, cifrati con la passphrase che scegli qui. " +
    "La protezione dipende SOLO da questa passphrase: sceglila lunga, e non perderla — senza, il backup è inutile.";
  a.addSecureTextField("Passphrase");
  a.addAction("Esporta");
  a.addCancelAction("Annulla");
  if ((await a.present()) !== 0) return;
  const pass = a.textFieldValue(0);
  if (!pass) return;
  try {
    const backup = await exportBackup(pass);
    const result = new Alert();
    result.title = "Backup pronto";
    result.message = backup;
    result.addAction("Copia negli Appunti");
    result.addCancelAction("Chiudi");
    if ((await result.present()) === 0) Pasteboard.copy(backup);
  } catch (e) {
    await showError(e);
  }
}

async function screenIdentity() {
  if (!identityLoaded) {
    const confirm = new Alert();
    confirm.title = "Nessuna identità";
    confirm.message = "Generarne una nuova, o ripristinarne una da un backup cifrato?";
    confirm.addAction("Genera nuova");
    confirm.addAction("Importa da backup");
    confirm.addCancelAction("Annulla");
    const scelta = await confirm.present();
    if (scelta === -1) return;
    if (scelta === 1) {
      const ok = await screenImportBackupFlow();
      if (!ok) return;
    } else {
      const { secret, public: pub } = await generateIdentity();
      currentSecret = secret;
      currentPublic = pub;
      identityLoaded = true;
      persistAll();
    }
  }

  const card = await getIdentityCard();
  const a = new Alert();
  a.title = "La mia presentazione";
  a.message =
    "Fingerprint: " +
    myFingerprint() +
    "\n\n" +
    card +
    "\n\nInvia questo testo al tuo contatto Android perché ti aggiunga.";
  a.addAction("Copia presentazione");
  a.addAction("Mostra QR (da inquadrare, non da scansionare qui)");
  a.addAction("Esporta backup cifrato");
  a.addAction("Rigenera identità (ATTENZIONE)");
  a.addCancelAction("Chiudi");
  const choice = await a.present();
  if (choice === 0) {
    Pasteboard.copy(card);
  } else if (choice === 1) {
    await showQrCode(card);
  } else if (choice === 2) {
    await screenExportBackupFlow();
  } else if (choice === 3) {
    const warn = new Alert();
    warn.title = "Sei sicuro?";
    warn.message =
      "Rigenerare l'identità rende illeggibili TUTTE le conversazioni esistenti, e i tuoi contatti smetteranno di riconoscerti. Non si può annullare.";
    warn.addDestructiveAction("Rigenera comunque");
    warn.addCancelAction("Annulla");
    if ((await warn.present()) === 0) {
      const { secret, public: pub } = await generateIdentity();
      currentSecret = secret;
      currentPublic = pub;
      persistAll();
    }
  }
}

async function handleLabelConflict(outcome, newPeerBytes) {
  const a = new Alert();
  a.title = "Nome già usato";
  a.message =
    "Questo nome è già assegnato a un'altra chiave.\n\nEsistente: " +
    outcome.existingFingerprint +
    "\nNuova: " +
    outcome.incomingFingerprint +
    "\n\nÈ la stessa persona con un telefono nuovo?";
  a.addDestructiveAction("Sì, sostituisci");
  a.addCancelAction("No, lascia stare");
  if ((await a.present()) === 0) {
    confirmKeyChange(outcome.existing, newPeerBytes);
  }
}

async function importContactFlow() {
  const a = new Alert();
  a.title = "Importa contatto";
  a.message = "Incolla qui la presentazione (kc/...) ricevuta dal tuo contatto Android.";
  a.addTextField("kc/...", "");
  a.addAction("Importa");
  a.addCancelAction("Annulla");
  if ((await a.present()) !== 0) return;
  const text = a.textFieldValue(0);
  if (!text) return;

  try {
    const item = decryptText(text);
    if (item.tag === "ownIdentityCard") {
      await showMessage("È la tua presentazione", "Hai incollato la tua stessa card, non quella di un contatto.");
      return;
    }
    if (item.tag !== "identityCard") {
      await showMessage("Non è una presentazione", "Il testo incollato non è una identity card MusyBoard.");
      return;
    }
    persistAll(); // the TOFU pin already happened inside mb_decrypt

    const nameAlert = new Alert();
    nameAlert.title = "Nome contatto";
    nameAlert.message = "Fingerprint: " + item.fingerprint + "\n\nCome si chiama?";
    nameAlert.addTextField("Nome", "");
    nameAlert.addAction("Salva");
    nameAlert.addCancelAction("Salta per ora");
    if ((await nameAlert.present()) === 0) {
      const label = nameAlert.textFieldValue(0);
      if (label) {
        const outcome = assignLabel(item.peer, label);
        if (outcome.kind === "conflict") {
          await handleLabelConflict(outcome, item.peer);
        }
      }
    }
    persistAll();
  } catch (e) {
    await showError(e);
  }
}

async function burnFlow(contact) {
  const warn = new Alert();
  warn.title = "Bruciare la conversazione?";
  warn.message =
    "Le chiavi con cui leggi i messaggi di " +
    (contact.label || "questo contatto") +
    " verranno distrutte QUI. È anche una richiesta per lui: se la sua app la onora, farà lo stesso dal suo lato. Non è recuperabile.";
  warn.addDestructiveAction("Brucia");
  warn.addCancelAction("Annulla");
  if ((await warn.present()) !== 0) return;
  try {
    const blob = await burnConversation(contact.public);
    persistAll();
    const result = new Alert();
    result.title = "Richiesta di rogo";
    result.message = blob + "\n\nInviala al tuo contatto perché distrugga anche lui la conversazione.";
    result.addAction("Copia");
    result.addCancelAction("Chiudi");
    if ((await result.present()) === 0) Pasteboard.copy(blob);
  } catch (e) {
    await showError(e);
  }
}

async function contactDetail(contact) {
  const a = new Alert();
  a.title = contact.label || "(senza nome)";
  a.message =
    "Fingerprint: " +
    fingerprintOf(contact.public) +
    (contact.verified
      ? "\n\n✓ Verificato"
      : "\n\nNon verificato — confronta il fingerprint di persona o su un altro canale prima di fidarti.");
  a.addAction("Segna come verificato");
  a.addAction("Imposta come destinatario per Cifra");
  a.addAction("Brucia conversazione");
  a.addDestructiveAction("Dimentica contatto");
  a.addCancelAction("Indietro");
  const choice = await a.present();
  if (choice === 0) {
    markVerified(contact.public);
    persistAll();
  } else if (choice === 1) {
    setCurrentPeer(contact.public);
    await showMessage("Fatto", "Ora 'Cifra un messaggio' scriverà a " + (contact.label || "questo contatto") + ".");
  } else if (choice === 2) {
    await burnFlow(contact);
  } else if (choice === 3) {
    await forgetFlow(contact);
  }
}

async function forgetFlow(contact) {
  const warn = new Alert();
  warn.title = "Dimenticare questo contatto?";
  warn.message =
    "Perdi il nome e il pin di sicurezza di " +
    (contact.label || "questo contatto") +
    ". Se scrive di nuovo, tornerà a comparire come mittente mai visto e verrà fissato di nuovo in silenzio — indistinguibile da qualcuno che si spacciasse per lui. Non è recuperabile.";
  warn.addDestructiveAction("Dimentica");
  warn.addCancelAction("Annulla");
  if ((await warn.present()) !== 0) return;
  forgetPeer(contact.public);
  persistAll();
}

async function screenContacts() {
  while (true) {
    const contacts = listContacts();
    const a = new Alert();
    a.title = "Contatti (" + contacts.length + ")";
    for (const c of contacts) {
      a.addAction((c.label || "(senza nome)") + (c.verified ? " ✓" : ""));
    }
    a.addAction("+ Importa nuovo contatto");
    a.addCancelAction("Indietro");
    const choice = await a.present();
    if (choice === -1) return;
    if (choice === contacts.length) {
      await importContactFlow();
      continue;
    }
    await contactDetail(contacts[choice]);
  }
}

/**
 * The header above a decrypted message: who wrote it, and how certain that is.
 *
 * In a one-to-one message a successful decryption **proves who wrote it**:
 * only the holder of that private key could produce the secret. Not saying so
 * would make a message from a contact and one from a stranger who knows your
 * public key look identical, and the system's only anti-MITM signal ("compared
 * in person") would never reach the user.
 *
 * For groups, K6 requires not only hiding the author but **saying** that it is
 * a group, how many people could read it, and that the author cannot be
 * established.
 */
function intestazioneMittente(item) {
  if (item.tag === "ownMessage") {
    const a = item.recipientLabel || fingerprintOf(item.recipient);
    return ["L'hai scritto tu", "a " + a];
  }

  if (item.gruppo) {
    // No name, per K6: the text is encrypted with a key every member has, so
    // any member could have rewritten it keeping the original slots. A name
    // next to rewritable text is worse than none: an invented guarantee.
    //
    // And the other half, required by K1 condition 2: a group has NO forward
    // secrecy, and keeping quiet about it would be the most convenient lie.
    return [
      "Messaggio di gruppo",
      "Potevano leggerlo in " + item.destinatari + ". Chi l'ha scritto non e' " +
      "stabilibile: chiunque del gruppo puo' averlo riscritto.\n" +
      "Un messaggio di gruppo non ha forward secrecy: resta apribile a chi " +
      "ottenga la chiave di uno qualsiasi dei membri.",
    ];
  }

  const s = item.senderStatus;
  if (s.kind === "new") {
    // Never-seen sender: the key was pinned just now (TOFU), and this is the
    // only moment the user can notice.
    return [
      "Mittente mai visto",
      "La sua chiave e' stata memorizzata ora. Da Contatti puoi dargli un nome " +
      "e confrontare l'impronta di persona:\n" + fingerprintOf(item.sender),
    ];
  }
  const nome = s.label || fingerprintOf(item.sender);
  return [
    s.verified ? "Da " + nome + " — confrontato di persona" : "Da " + nome,
    s.verified
      ? ""
      : "Non hai ancora confrontato la sua impronta di persona: da sola la " +
        "memorizzazione non esclude che qualcuno si sia messo in mezzo al " +
        "primo contatto.",
  ];
}

async function showDecryptedResult(item) {
  if (item.tag === "message" || item.tag === "ownMessage") {
    const [titolo, sottotitolo] = intestazioneMittente(item);
    const quando = new Date(Number(item.sentAtUnix) * 1000).toLocaleString();
    // The date is only shown: it is authenticated but not verifiable, and
    // decision C forbids automatic decisions on it. It helps a human notice a
    // reposted message.
    const html =
      "<html><body style='font-family: -apple-system, sans-serif; " +
      "padding: 24px; word-wrap: break-word;'>" +
      "<div style='font-size: 15px; color: #666;'>" +
      "<b>" + escapeHtml(titolo) + "</b>" +
      (sottotitolo ? "<br>" + escapeHtml(sottotitolo).replace(/\n/g, "<br>") : "") +
      "<br>Composto il " + escapeHtml(quando) +
      "</div><hr style='border:none;border-top:1px solid #ddd;margin:16px 0;'>" +
      "<div style='font-size: 20px; white-space: pre-wrap;'>" +
      escapeHtml(item.text) +
      "</div></body></html>";
    const wv = new WebView();
    await wv.loadHTML(html);
    await wv.present(true);
  } else if (item.tag === "identityCard" || item.tag === "ownIdentityCard") {
    await showMessage(
      "Presentazione",
      "Questo testo è una identity card, non un messaggio. Usa 'Contatti → Importa' per aggiungerla."
    );
  } else if (item.tag === "burned") {
    await showMessage("Richiesta di rogo ricevuta", "Le chiavi per questa conversazione sono state distrutte.");
  }
}

async function screenDecrypt() {
  const a = new Alert();
  a.title = "Decifra";
  a.message = "Incolla il testo cifrato, o lascia vuoto per leggerlo dagli Appunti.";
  a.addTextField("kc/...", "");
  a.addAction("Decifra");
  a.addCancelAction("Annulla");
  if ((await a.present()) !== 0) return;
  let text = a.textFieldValue(0);
  if (!text) text = Pasteboard.paste() || "";
  if (!text) {
    await showMessage("Niente da decifrare", "Il campo e gli Appunti sono vuoti.");
    return;
  }
  try {
    const item = decryptText(text);
    persistAll();
    await showDecryptedResult(item);
  } catch (e) {
    await showError(e);
  }
}

async function pickContact(title) {
  const contacts = listContacts();
  if (contacts.length === 0) {
    await showMessage("Nessun contatto", "Importa prima un contatto da 'Contatti'.");
    return null;
  }
  const pick = new Alert();
  pick.title = title;
  for (const c of contacts) pick.addAction(c.label || "(senza nome)");
  pick.addCancelAction("Annulla");
  const idx = await pick.present();
  return idx === -1 ? null : contacts[idx];
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function findContactByPublic(publicBytes) {
  return listContacts().find((c) => bytesEqual(c.public, publicBytes)) || null;
}

async function screenEncrypt() {
  let contact = null;
  const currentPublic = getCurrentPeer();
  if (currentPublic) {
    const known = findContactByPublic(currentPublic);
    if (known) {
      const a = new Alert();
      a.title = "Destinatario";
      a.message = "Continui a scrivere a " + (known.label || "(senza nome)") + "?";
      a.addAction("Sì, continua");
      a.addAction("Scegli un altro contatto");
      a.addCancelAction("Annulla");
      const choice = await a.present();
      if (choice === -1) return;
      if (choice === 0) contact = known;
    }
  }
  if (!contact) {
    contact = await pickContact("Cifra per...");
    if (!contact) return;
    setCurrentPeer(contact.public);
  }

  const a = new Alert();
  a.title = "Testo da cifrare";
  a.addTextField("Scrivi qui...", "");
  a.addAction("Cifra");
  a.addCancelAction("Annulla");
  if ((await a.present()) !== 0) return;
  const text = a.textFieldValue(0);
  if (!text) return;
  try {
    const blob = await encryptText(text);
    persistAll();
    const result = new Alert();
    result.title = "Cifrato";
    result.message = blob;
    result.addAction("Copia negli Appunti");
    result.addCancelAction("Chiudi");
    if ((await result.present()) === 0) Pasteboard.copy(blob);
  } catch (e) {
    await showError(e);
  }
}

async function screenSendFile() {
  const contact = await pickContact("Invia file a...");
  if (!contact) return;
  let path;
  try {
    path = await DocumentPicker.openFile();
  } catch (e) {
    return; // cancelled by the user
  }
  try {
    const fm = FileManager.local();
    const data = fm.read(path);
    const contentBytes = new Uint8Array(data.getBytes());
    const name = fm.fileName(path, true);
    const mime = guessMimeType(name);

    const blob = await encryptFileFor(contact.public, name, mime, contentBytes);
    persistAll();

    const outPath = fm.joinPath(
      fm.cacheDirectory(),
      "kc-" + Math.floor(Math.random() * 1e9) + ".kc"
    );
    try {
      fm.write(outPath, bytesToScriptableData(blob));
      await ShareSheet.present([outPath]);
    } finally {
      // Consistent with the core's G5: even if the sheet is cancelled or fails,
      // no list of "how many files you sent and when" is left behind.
      if (fm.fileExists(outPath)) fm.remove(outPath);
    }
  } catch (e) {
    await showError(e);
  }
}

async function screenReceiveFile() {
  let path;
  try {
    path = await DocumentPicker.openFile();
  } catch (e) {
    return;
  }
  try {
    const fm = FileManager.local();
    const data = fm.read(path);
    const bytes = new Uint8Array(data.getBytes());
    const incoming = decryptFileBytes(bytes);
    persistAll();

    const info = new Alert();
    info.title = "Allegato ricevuto";
    info.message =
      "Nome: " +
      incoming.name +
      "\nTipo: " +
      incoming.mime +
      "\nDimensione: " +
      incoming.content.length +
      " byte" +
      (incoming.nostro ? "\n\n(lo avevi mandato tu)" : "");
    info.addAction("Salva...");
    info.addCancelAction("Chiudi");
    if ((await info.present()) === 0) {
      // A throwaway directory keeps the sanitised original name without risk
      // of colliding with another temporary attachment.
      const tmpDir = fm.joinPath(
        fm.temporaryDirectory(),
        "kc-open-" + Math.floor(Math.random() * 1e9)
      );
      const tmpPath = fm.joinPath(tmpDir, safeAttachmentName(incoming.name));
      try {
        fm.createDirectory(tmpDir);
        fm.write(tmpPath, bytesToScriptableData(incoming.content));
        await DocumentPicker.export(tmpPath);
      } finally {
        // The plaintext must not survive a cancellation or a document picker
        // error either.
        if (fm.fileExists(tmpPath)) fm.remove(tmpPath);
        if (fm.fileExists(tmpDir)) fm.remove(tmpDir);
      }
    }
  } catch (e) {
    await showError(e);
  }
}

/** Multiple contact selection. Scriptable has no native checkbox in `Alert`, so
 * it is simulated with a loop: each tap toggles a tick, a final button
 * confirms. */
async function pickMultipleContacts(title) {
  const contacts = listContacts();
  if (contacts.length < 2) {
    await showMessage("Servono almeno 2 contatti", "Un gruppo ha bisogno di almeno due destinatari.");
    return null;
  }
  const selected = new Set();
  while (true) {
    const a = new Alert();
    a.title = title;
    a.message = selected.size + " selezionati";
    contacts.forEach((c, i) => {
      const mark = selected.has(i) ? "✓ " : "☐ ";
      a.addAction(mark + (c.label || "(senza nome)"));
    });
    a.addAction("Fatto");
    a.addCancelAction("Annulla");
    const choice = await a.present();
    if (choice === -1) return null;
    if (choice === contacts.length) {
      if (selected.size < 2) {
        await showMessage("Troppo pochi", "Seleziona almeno due contatti.");
        continue;
      }
      return Array.from(selected).map((i) => contacts[i]);
    }
    if (selected.has(choice)) selected.delete(choice);
    else selected.add(choice);
  }
}

async function screenEncryptGroup() {
  const chosen = await pickMultipleContacts("Cifra per il gruppo...");
  if (!chosen) return;
  const a = new Alert();
  a.title = "Testo (gruppo, " + chosen.length + " destinatari)";
  a.message =
    "Nessuna forward secrecy per i messaggi di gruppo, per come e' fatto il formato — e chi lo riceve non può sapere quale membro del gruppo lo ha scritto davvero.";
  a.addTextField("Scrivi qui...", "");
  a.addAction("Cifra");
  a.addCancelAction("Annulla");
  if ((await a.present()) !== 0) return;
  const text = a.textFieldValue(0);
  if (!text) return;
  try {
    const blob = await encryptGroup(
      chosen.map((c) => c.public),
      text
    );
    persistAll();
    const result = new Alert();
    result.title = "Cifrato per il gruppo";
    result.message = blob;
    result.addAction("Copia negli Appunti");
    result.addCancelAction("Chiudi");
    if ((await result.present()) === 0) Pasteboard.copy(blob);
  } catch (e) {
    await showError(e);
  }
}

async function mainMenu() {
  while (true) {
    const a = new Alert();
    a.title = "MusyBoard";
    a.message = identityLoaded ? "Io: " + myFingerprint() : "Nessuna identità caricata";
    a.addAction("La mia identità");
    a.addAction("Contatti");
    a.addAction("Decifra un messaggio");
    a.addAction("Cifra un messaggio");
    a.addAction("Cifra per un gruppo");
    a.addAction("Invia un file cifrato");
    a.addAction("Apri un file cifrato ricevuto");
    a.addCancelAction("Chiudi");
    const choice = await a.present();
    if (choice === -1) return;
    try {
      if (choice === 0) await screenIdentity();
      else if (choice === 1) await screenContacts();
      else if (choice === 2) await screenDecrypt();
      else if (choice === 3) await screenEncrypt();
      else if (choice === 4) await screenEncryptGroup();
      else if (choice === 5) await screenSendFile();
      else if (choice === 6) await screenReceiveFile();
    } catch (e) {
      await showError(e);
    }
  }
}

// -----------------------------------------------------------------------
// Entry from Shortcuts.
//
// The two Shortcuts (decrypt and encrypt) pass their
// text prefixed with a marker ("MB_DECRYPT:"/"MB_ENCRYPT:"), added by a "Text"
// action inside the Shortcut (see INSTALL.md). The marker states the intent
// without guessing from the content: two Shortcuts stay two distinct actions.
// -----------------------------------------------------------------------

const MARKER_DECRYPT = "MB_DECRYPT:";
const MARKER_ENCRYPT = "MB_ENCRYPT:";

function describeError(e) {
  return e && e.message ? e.message : String(e);
}

function formatIncomingItemForShortcut(item) {
  if (item.tag === "message" || item.tag === "ownMessage") return item.text;
  if (item.tag === "identityCard") return "[presentazione ricevuta — apri MusyBoard per importarla]";
  if (item.tag === "ownIdentityCard") return "[questa è la tua stessa presentazione]";
  if (item.tag === "burned") return "[richiesta di rogo ricevuta ed eseguita]";
  return "[esito sconosciuto]";
}

async function ensureCurrentPeerForShortcut() {
  const contacts = listContacts();
  if (contacts.length === 0) {
    throw new Error("nessun contatto salvato: apri MusyBoard e importane uno prima");
  }
  if (contacts.length === 1) {
    setCurrentPeer(contacts[0].public);
    return;
  }
  const chosen = await pickContact("Cifra per...");
  if (!chosen) throw new Error("annullato");
  setCurrentPeer(chosen.public);
}

async function shortcutsEntry() {
  const param = args.shortcutParameter;
  if (typeof param !== "string") return false;

  if (param.indexOf(MARKER_DECRYPT) === 0) {
    const text = param.slice(MARKER_DECRYPT.length);
    try {
      const item = decryptText(text);
      persistAll();
      Script.setShortcutOutput(formatIncomingItemForShortcut(item));
    } catch (e) {
      Script.setShortcutOutput("[errore MusyBoard: " + describeError(e) + "]");
    }
    return true;
  }

  if (param.indexOf(MARKER_ENCRYPT) === 0) {
    const text = param.slice(MARKER_ENCRYPT.length);
    try {
      if (!identityLoaded) throw new MusyBoardError(92);
      await ensureCurrentPeerForShortcut();
      const blob = await encryptText(text);
      persistAll();
      Script.setShortcutOutput(blob);
    } catch (e) {
      Script.setShortcutOutput("[errore MusyBoard: " + describeError(e) + "]");
    }
    return true;
  }

  return false;
}

// -----------------------------------------------------------------------
// Entry point.
// -----------------------------------------------------------------------

async function main() {
  await bootstrap();
  const handled = await shortcutsEntry();
  if (handled) {
    Script.complete();
    return;
  }
  if (!identityLoaded) {
    await screenIdentity();
  }
  await mainMenu();
  Script.complete();
}

// The guard on `FileManager` (a Scriptable global, never present elsewhere)
// keeps this file loadable in any JS engine without starting the app: that is
// how `scriptable/test-codec.js` checks the pure logic (encoding,
// ByteReader/Writer, codec) outside Scriptable, without a second copy that
// could drift.
if (typeof FileManager !== "undefined") {
  await main();
}

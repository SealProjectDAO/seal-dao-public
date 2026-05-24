// Minimal QR encoder — byte mode, L error correction, versions 1-5.
//
// Capacity is 106 bytes at v5, more than enough for a Seal address
// (~64 chars including the bech32m HRP). Auto-picks the smallest
// version that fits. Single fixed mask (pattern 0: row+col even).
// Most QR readers handle a fixed mask fine for short URLs and
// addresses — proper mask selection by penalty score is the next
// step if scan reliability dips.
//
// API: window.SealQR.draw(canvas, text, scale = 4) → {size, version}.
// Throws if the text exceeds v5 capacity.
//
// No external deps. ASCII-safe; non-ASCII is UTF-8 encoded by
// TextEncoder, which a byte-mode QR represents fine but may not be
// rendered correctly by every reader (bech32m is ASCII).
//
// References: ISO/IEC 18004:2015, Annex N (QR specification).

(function () {
  // ── GF(256) tables ────────────────────────────────────────────────
  // Primitive polynomial 0x11D = x^8 + x^4 + x^3 + x^2 + 1.
  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);
  (function buildTables() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11D;
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return EXP[LOG[a] + LOG[b]];
  }

  // Generator polynomial of degree `n`: prod_{i=0..n-1} (x - alpha^i).
  function rsGenerator(n) {
    let g = new Uint8Array([1]);
    for (let i = 0; i < n; i++) {
      const next = new Uint8Array(g.length + 1);
      for (let j = 0; j < g.length; j++) {
        next[j] ^= g[j];
        next[j + 1] ^= gfMul(g[j], EXP[i]);
      }
      g = next;
    }
    return g;
  }

  // Compute Reed-Solomon error-correction codewords for `data`.
  function rsEncode(data, ecLen) {
    const gen = rsGenerator(ecLen);
    const buf = new Uint8Array(data.length + ecLen);
    buf.set(data, 0);
    for (let i = 0; i < data.length; i++) {
      const factor = buf[i];
      if (factor === 0) continue;
      for (let j = 0; j < gen.length; j++) {
        buf[i + j] ^= gfMul(gen[j], factor);
      }
    }
    return buf.slice(data.length);
  }

  // ── Per-version (L EC) parameters ─────────────────────────────────
  // Versions 1-5: single block. align = center coord of the lone
  // alignment pattern (null for v1).
  const VERSIONS = {
    1: { dataCw: 19, ecCw: 7,  align: null },
    2: { dataCw: 34, ecCw: 10, align: 18 },
    3: { dataCw: 55, ecCw: 15, align: 22 },
    4: { dataCw: 80, ecCw: 20, align: 26 },
    5: { dataCw: 108, ecCw: 26, align: 30 },
  };

  function pickVersion(byteLen) {
    // Header: 4 mode bits + 8 length bits = 12. Total bits = dataCw*8.
    for (let v = 1; v <= 5; v++) {
      if (byteLen * 8 + 12 <= VERSIONS[v].dataCw * 8) return v;
    }
    throw new Error("text exceeds QR v5 byte-mode capacity (106 bytes)");
  }

  // ── Bitstream construction ────────────────────────────────────────
  function buildCodewords(text, version) {
    const data = new TextEncoder().encode(text);
    const dataCw = VERSIONS[version].dataCw;
    const totalBits = dataCw * 8;

    const bits = [];
    const push = (v, n) => {
      for (let i = n - 1; i >= 0; i--) bits.push((v >> i) & 1);
    };

    push(0b0100, 4);          // byte mode
    push(data.length, 8);     // length (8 bits for v1-9)
    for (const b of data) push(b, 8);

    // Terminator (up to 4 zeros, but no further than `totalBits`).
    for (let i = 0; i < 4 && bits.length < totalBits; i++) bits.push(0);
    while (bits.length % 8) bits.push(0);
    const padBytes = [0xEC, 0x11];
    let padIdx = 0;
    while (bits.length < totalBits) push(padBytes[padIdx++ % 2], 8);

    const bytes = new Uint8Array(dataCw);
    for (let i = 0; i < dataCw; i++) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
      bytes[i] = b;
    }
    return bytes;
  }

  // ── Format info (L EC + mask 0) ───────────────────────────────────
  // BCH(15,5) over data 0b01000 (L=01, mask=000), then XOR 0x5412.
  const FORMAT_INFO = (function () {
    const data = 0b01000;
    let rem = 0;
    let v = data << 10;
    for (let i = 14; i >= 10; i--) {
      if (v & (1 << i)) v ^= 0b10100110111 << (i - 10);
    }
    rem = v;
    return ((data << 10) | rem) ^ 0x5412;
  })();

  // ── Module placement ──────────────────────────────────────────────
  // Build the QR matrix: m[r][c] = 0 (light), 1 (dark), -1 (data slot
  // not yet filled). Reserved bits (function patterns + format info)
  // are flagged in `reserved`.
  function buildMatrix(version, finalBytes) {
    const size = 17 + 4 * version;
    const m = Array.from({ length: size }, () =>
      new Int8Array(size).fill(-1),
    );
    const reserved = Array.from({ length: size }, () =>
      new Uint8Array(size),
    );

    const set = (r, c, v) => {
      m[r][c] = v;
      reserved[r][c] = 1;
    };

    // Finder pattern (7x7) at (r, c): outer ring + 3x3 center, with
    // 1px white separator outward.
    function placeFinder(r, c) {
      for (let dr = -1; dr <= 7; dr++) {
        for (let dc = -1; dc <= 7; dc++) {
          const rr = r + dr;
          const cc = c + dc;
          if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
          let dark = 0;
          if (dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6) {
            const onBorder =
              dr === 0 || dr === 6 || dc === 0 || dc === 6;
            const inCenter =
              dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
            dark = onBorder || inCenter ? 1 : 0;
          }
          set(rr, cc, dark);
        }
      }
    }

    placeFinder(0, 0);
    placeFinder(0, size - 7);
    placeFinder(size - 7, 0);

    // Timing patterns (alternating black/white) on row 6 and col 6.
    for (let i = 8; i < size - 8; i++) {
      const v = i % 2 === 0 ? 1 : 0;
      set(6, i, v);
      set(i, 6, v);
    }

    // Alignment pattern: 5x5 with dark border, white inner ring,
    // single dark center. v2-5 have a single pattern; v1 has none.
    const align = VERSIONS[version].align;
    if (align !== null) {
      const ar = align;
      const ac = align;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const onBorder = Math.max(Math.abs(dr), Math.abs(dc)) === 2;
          const center = dr === 0 && dc === 0;
          set(ar + dr, ac + dc, onBorder || center ? 1 : 0);
        }
      }
    }

    // Dark module (always set, beside the bottom-left finder).
    set(size - 8, 8, 1);

    // Reserve format-info cells (we'll write the actual bits after
    // the data is placed and masked).
    for (let i = 0; i <= 8; i++) {
      reserved[8][i] = 1;
      reserved[i][8] = 1;
    }
    for (let i = 0; i < 8; i++) {
      reserved[size - 1 - i][8] = 1;
      reserved[8][size - 1 - i] = 1;
    }

    // ── Data placement: zigzag from bottom-right, two columns at a
    // time, skipping column 6 (timing).
    const bits = [];
    for (const b of finalBytes) {
      for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
    }
    let bi = 0;
    let upward = true;
    for (let col = size - 1; col > 0; col -= 2) {
      if (col === 6) col--;
      for (let i = 0; i < size; i++) {
        const r = upward ? size - 1 - i : i;
        for (let dc = 0; dc < 2; dc++) {
          const c = col - dc;
          if (reserved[r][c]) continue;
          let bit = bi < bits.length ? bits[bi++] : 0;
          // Mask 0: invert where (row + col) % 2 == 0.
          if ((r + c) % 2 === 0) bit ^= 1;
          m[r][c] = bit;
        }
      }
      upward = !upward;
    }

    // ── Format info: 15 bits split across two locations.
    const fmt = FORMAT_INFO;
    // Bits 0..5 along col 8 top: rows 0..5
    // Bit 6: row 7 col 8, bit 7: row 8 col 8, bit 8: row 8 col 7
    // Bits 9..14: row 8 cols 5..0
    const fmtBits = [];
    for (let i = 14; i >= 0; i--) fmtBits.push((fmt >> i) & 1);
    // Top-left placement (read from MSB):
    //   col=8, rows 0..5 → bits 14..9
    //   col=8, row 7    → bit 8
    //   col=8, row 8    → bit 7
    //   row=8, col 7    → bit 6
    //   row=8, cols 5..0 → bits 5..0
    for (let i = 0; i < 6; i++) m[i][8] = fmtBits[14 - i];
    m[7][8] = fmtBits[14 - 6];
    m[8][8] = fmtBits[14 - 7];
    m[8][7] = fmtBits[14 - 8];
    for (let i = 0; i < 6; i++) m[8][5 - i] = fmtBits[14 - 9 - i];
    // Mirror placement (bottom + right):
    //   row=8, col=size-1..size-8 → bits 14..7
    //   col=8, row=size-7..size-1 → bits 6..0
    for (let i = 0; i < 8; i++) m[8][size - 1 - i] = fmtBits[i];
    for (let i = 0; i < 7; i++) m[size - 1 - i][8] = fmtBits[8 + i];

    return { matrix: m, size };
  }

  // ── Public draw ───────────────────────────────────────────────────
  function draw(canvas, text, scale) {
    const v = pickVersion(new TextEncoder().encode(text).length);
    const data = buildCodewords(text, v);
    const ec = rsEncode(data, VERSIONS[v].ecCw);
    const final = new Uint8Array(data.length + ec.length);
    final.set(data, 0);
    final.set(ec, data.length);

    const { matrix, size } = buildMatrix(v, final);
    const s = scale || 4;
    const quiet = 4; // 4-module quiet zone (per spec)
    const px = (size + 2 * quiet) * s;
    canvas.width = px;
    canvas.height = px;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, px, px);
    ctx.fillStyle = "#000";
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (matrix[r][c] === 1) {
          ctx.fillRect((c + quiet) * s, (r + quiet) * s, s, s);
        }
      }
    }
    return { size, version: v };
  }

  if (typeof window !== "undefined") {
    window.SealQR = { draw };
  }
  if (typeof globalThis !== "undefined") {
    globalThis.SealQR = { draw };
  }
})();

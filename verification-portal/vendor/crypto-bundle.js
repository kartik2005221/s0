/**
 * TrustWipe Pure JavaScript Cryptographic Bundle
 * Contains:
 *  - TweetNaCl (Public Domain Ed25519 signature verification)
 *  - Pure JS SHA-256 (FIPS 180-4)
 *  - Base64 / Base64URL / Hex encoders & decoders
 *  - ASN.1 SubjectPublicKeyInfo Ed25519 parser & fingerprint calculator
 *
 * Fully self-contained. Zero external dependencies. Runs in any browser or static context.
 */
(function(root, factory) {
  if (typeof define === "function" && define.amd) {
    define([], factory);
  } else if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.TrustWipeCrypto = factory();
  }
}(typeof self !== "undefined" ? self : this, function() {
  "use strict";

  // -------------------------------------------------------------------------
  // SHA-256 Implementation (FIPS 180-4)
  // -------------------------------------------------------------------------
  var K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function rotr(w, n) { return (w >>> n) | (w << (32 - n)); }

  function sha256(bytes) {
    if (typeof bytes === "string") {
      bytes = utf8ToBytes(bytes);
    }
    var l = bytes.length;
    var bitLen = l * 8;
    var padLen = (l % 64 < 56) ? (56 - (l % 64)) : (120 - (l % 64));
    var totalLen = l + padLen + 8;
    var padded = new Uint8Array(totalLen);
    padded.set(bytes);
    padded[l] = 0x80;
    
    // Append 64-bit length big-endian
    var view = new DataView(padded.buffer);
    view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(totalLen - 4, bitLen >>> 0, false);

    var H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);

    var W = new Uint32Array(64);

    for (var i = 0; i < totalLen; i += 64) {
      for (var t = 0; t < 16; t++) {
        W[t] = view.getUint32(i + (t * 4), false);
      }
      for (var t = 16; t < 64; t++) {
        var s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        var s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
      }

      var a = H[0], b = H[1], c = H[2], d = H[3];
      var e = H[4], f = H[5], g = H[6], h = H[7];

      for (var t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ ((~e) & g);
        var temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) >>> 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }

      H[0] = (H[0] + a) >>> 0;
      H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0;
      H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0;
      H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0;
      H[7] = (H[7] + h) >>> 0;
    }

    var out = new Uint8Array(32);
    var outView = new DataView(out.buffer);
    for (var j = 0; j < 8; j++) {
      outView.setUint32(j * 4, H[j], false);
    }
    return out;
  }

  function sha256Hex(bytes) {
    return bytesToHex(sha256(bytes));
  }

  // -------------------------------------------------------------------------
  // TweetNaCl - Ed25519 Verify (Portion from TweetNaCl.js by Dmitry Chestnykh)
  // -------------------------------------------------------------------------
  var gf = function(init) {
    var r = new Float64Array(16);
    if (init) for (var i = 0; i < init.length; i++) r[i] = init[i];
    return r;
  };

  var gf0 = gf(),
      gf1 = gf([1]),
      _121665 = gf([0xdb41, 1]),
      D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]),
      D2 = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xefef, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]),
      I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xa294, 0x0155, 0x5603, 0x9ee5, 0x8d28, 0x320b, 0x654c, 0x6f72, 0x2b40, 0x5a52, 0x2a0a]);

  function car25519(o) {
    var c;
    for (var i = 0; i < 16; i++) {
      o[i] += 65536;
      c = Math.floor(o[i] / 65536);
      o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i === 15 ? 1 : 0);
      o[i] -= c * 65536;
    }
  }

  function sel25519(p, q, b) {
    var t, c = ~(b - 1);
    for (var i = 0; i < 16; i++) {
      t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  }

  function pack25519(o, n) {
    var i, j, b;
    var m = gf(), t = gf();
    for (i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      b = (m[15] >> 16) & 1;
      m[14] &= 0xffff;
      sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
      o[2 * i] = t[i] & 0xff;
      o[2 * i + 1] = t[i] >> 8;
    }
  }

  function unpack25519(o, n) {
    for (var i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
  }

  function A(o, a, b) { for (var i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
  function Z(o, a, b) { for (var i = 0; i < 16; i++) o[i] = a[i] - b[i]; }
  function M(o, a, b) {
    var v, c = new Float64Array(31);
    for (var i = 0; i < 16; i++) {
      for (var j = 0; j < 16; j++) {
        c[i + j] += a[i] * b[j];
      }
    }
    for (var i = 0; i < 15; i++) c[i] += 38 * c[i + 16];
    for (var i = 0; i < 16; i++) o[i] = c[i];
    car25519(o);
    car25519(o);
  }
  function S(o, a) { M(o, a, a); }
  function inv25519(o, i) {
    var c = gf();
    for (var a = 0; a < 16; a++) c[a] = i[a];
    for (var a = 253; a >= 0; a--) {
      S(c, c);
      if (a !== 2 && a !== 4) M(c, c, i);
    }
    for (var a = 0; a < 16; a++) o[a] = c[a];
  }

  function crypto_hash(out, m, n) {
    // SHA-512 for Ed25519
    var h = sha512(m.subarray(0, n));
    out.set(h);
    return 0;
  }

  // SHA-512 implementation
  function sha512(msg) {
    var K512 = [
      0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
      0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
      0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
      0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
      0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
      0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
      0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
      0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
      0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
      0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
      0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
      0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
      0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
      0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
      0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
      0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
      0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
      0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
      0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
      0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
    ];

    var l = msg.length;
    var bitLenHi = Math.floor(l / 0x20000000);
    var bitLenLo = (l * 8) >>> 0;
    var padLen = (l % 128 < 112) ? (112 - (l % 128)) : (240 - (l % 128));
    var totalLen = l + padLen + 16;
    var padded = new Uint8Array(totalLen);
    padded.set(msg);
    padded[l] = 0x80;
    var dv = new DataView(padded.buffer);
    dv.setUint32(totalLen - 8, bitLenHi, false);
    dv.setUint32(totalLen - 4, bitLenLo, false);

    var H = [
      0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b,
      0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
      0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
      0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179
    ];

    var W = new Int32Array(160);

    for (var i = 0; i < totalLen; i += 128) {
      for (var t = 0; t < 16; t++) {
        W[2 * t] = dv.getUint32(i + (t * 8), false);
        W[2 * t + 1] = dv.getUint32(i + (t * 8) + 4, false);
      }
      for (var t = 16; t < 80; t++) {
        // gamma0
        var t15h = W[2 * (t - 15)], t15l = W[2 * (t - 15) + 1];
        var s0h = ((t15h >>> 1) | (t15l << 31)) ^ ((t15h >>> 8) | (t15l << 24)) ^ (t15h >>> 7);
        var s0l = ((t15l >>> 1) | (t15h << 31)) ^ ((t15l >>> 8) | (t15h << 24)) ^ ((t15l >>> 7) | (t15h << 25));

        // gamma1
        var t2h = W[2 * (t - 2)], t2l = W[2 * (t - 2) + 1];
        var s1h = ((t2h >>> 19) | (t2l << 13)) ^ ((t2l >>> 29) | (t2h << 3)) ^ (t2h >>> 6);
        var s1l = ((t2l >>> 19) | (t2h << 13)) ^ ((t2h >>> 29) | (t2l << 3)) ^ ((t2l >>> 6) | (t2h << 26));

        var t16h = W[2 * (t - 16)], t16l = W[2 * (t - 16) + 1];
        var t7h = W[2 * (t - 7)], t7l = W[2 * (t - 7) + 1];

        var suml = (t16l + s0l + t7l + s1l) >>> 0;
        var carry = Math.floor((t16l + s0l + t7l + s1l) / 0x100000000);
        var sumh = (t16h + s0h + t7h + s1h + carry) >>> 0;

        W[2 * t] = sumh;
        W[2 * t + 1] = suml;
      }

      var a0 = H[0], a1 = H[1], b0 = H[2], b1 = H[3],
          c0 = H[4], c1 = H[5], d0 = H[6], d1 = H[7],
          e0 = H[8], e1 = H[9], f0 = H[10], f1 = H[11],
          g0 = H[12], g1 = H[13], h0 = H[14], h1 = H[15];

      for (var t = 0; t < 80; t++) {
        // sigma1
        var S1h = ((e0 >>> 14) | (e1 << 18)) ^ ((e0 >>> 18) | (e1 << 14)) ^ ((e1 >>> 9) | (e0 << 23));
        var S1l = ((e1 >>> 14) | (e0 << 18)) ^ ((e1 >>> 18) | (e0 << 14)) ^ ((e0 >>> 9) | (e1 << 23));

        // ch
        var chh = (e0 & f0) ^ ((~e0) & g0);
        var chl = (e1 & f1) ^ ((~e1) & g1);

        var kt0 = K512[2 * t], kt1 = K512[2 * t + 1];
        var wt0 = W[2 * t], wt1 = W[2 * t + 1];

        var t1l = (h1 + S1l + chl + kt1 + wt1) >>> 0;
        var t1carry = Math.floor((h1 + S1l + chl + kt1 + wt1) / 0x100000000);
        var t1h = (h0 + S1h + chh + kt0 + wt0 + t1carry) >>> 0;

        // sigma0
        var S0h = ((a0 >>> 28) | (a1 << 4)) ^ ((a1 >>> 2) | (a0 << 30)) ^ ((a1 >>> 7) | (a0 << 25));
        var S0l = ((a1 >>> 28) | (a0 << 4)) ^ ((a0 >>> 2) | (a1 << 30)) ^ ((a0 >>> 7) | (a1 << 25));

        // maj
        var majh = (a0 & b0) ^ (a0 & c0) ^ (b0 & c0);
        var majl = (a1 & b1) ^ (a1 & c1) ^ (b1 & c1);

        var t2l = (S0l + majl) >>> 0;
        var t2carry = Math.floor((S0l + majl) / 0x100000000);
        var t2h = (S0h + majh + t2carry) >>> 0;

        h0 = g0; h1 = g1;
        g0 = f0; g1 = f1;
        f0 = e0; f1 = e1;
        var el = (d1 + t1l) >>> 0;
        var eh = (d0 + t1h + Math.floor((d1 + t1l) / 0x100000000)) >>> 0;
        e0 = eh; e1 = el;
        d0 = c0; d1 = c1;
        c0 = b0; c1 = b1;
        b0 = a0; b1 = a1;
        var al = (t1l + t2l) >>> 0;
        var ah = (t1h + t2h + Math.floor((t1l + t2l) / 0x100000000)) >>> 0;
        a0 = ah; a1 = al;
      }

      H[0] = (H[0] + a0 + Math.floor((H[1] + a1) / 0x100000000)) >>> 0;
      H[1] = (H[1] + a1) >>> 0;
      H[2] = (H[2] + b0 + Math.floor((H[3] + b1) / 0x100000000)) >>> 0;
      H[3] = (H[3] + b1) >>> 0;
      H[4] = (H[4] + c0 + Math.floor((H[5] + c1) / 0x100000000)) >>> 0;
      H[5] = (H[5] + c1) >>> 0;
      H[6] = (H[6] + d0 + Math.floor((H[7] + d1) / 0x100000000)) >>> 0;
      H[7] = (H[7] + d1) >>> 0;
      H[8] = (H[8] + e0 + Math.floor((H[9] + e1) / 0x100000000)) >>> 0;
      H[9] = (H[9] + e1) >>> 0;
      H[10] = (H[10] + f0 + Math.floor((H[11] + f1) / 0x100000000)) >>> 0;
      H[11] = (H[11] + f1) >>> 0;
      H[12] = (H[12] + g0 + Math.floor((H[13] + g1) / 0x100000000)) >>> 0;
      H[13] = (H[13] + g1) >>> 0;
      H[14] = (H[14] + h0 + Math.floor((H[15] + h1) / 0x100000000)) >>> 0;
      H[15] = (H[15] + h1) >>> 0;
    }

    var out = new Uint8Array(64);
    var outDv = new DataView(out.buffer);
    for (var j = 0; j < 16; j++) {
      outDv.setUint32(j * 4, H[j], false);
    }
    return out;
  }

  function vn(x, xi, y, yi, n) {
    var d = 0;
    for (var i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i];
    return (1 & ((d - 1) >>> 8)) - 1;
  }

  function crypto_sign_verify_detached(sig, msg, pk) {
    var p = [gf(), gf(), gf(), gf()],
        q = [gf(), gf(), gf(), gf()];
    var t = new Uint8Array(32),
        r = new Uint8Array(32),
        h = new Uint8Array(64);

    if (sig.length !== 64 || pk.length !== 32) return -1;
    if (unpackneg_ptr(q, pk)) return -1;

    var sm = new Uint8Array(64 + msg.length);
    sm.set(sig.subarray(0, 32));
    sm.set(pk, 32);
    sm.set(msg, 64);

    crypto_hash(h, sm, sm.length);
    reduce(h);

    var sc = new Uint8Array(32);
    sc.set(sig.subarray(32, 64));
    scalarmult(p, q, h);
    scalarbase(q, sc);
    add(p, q);
    pack(t, p);

    return vn(sig, 0, t, 0, 32);
  }

  function unpackneg_ptr(r, p) {
    var t = gf(), chk = gf(), num = gf(), den = gf(), den2 = gf(), den4 = gf(), den6 = gf();
    unpack25519(r[1], p);
    A(r[2], gf1, gf0);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);
    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);
    inv25519(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);
    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) {
      M(r[0], r[0], I);
      S(chk, r[0]);
      M(chk, chk, den);
      if (neq25519(chk, num)) return -1;
    }
    if (par25519(r[0]) === (p[31] >> 7)) Z(r[0], gf0, r[0]);
    M(r[3], r[0], r[1]);
    return 0;
  }

  function neq25519(a, b) {
    var c = new Uint8Array(32), d = new Uint8Array(32);
    pack25519(c, a);
    pack25519(d, b);
    return vn(c, 0, d, 0, 32);
  }

  function par25519(a) {
    var d = new Uint8Array(32);
    pack25519(d, a);
    return d[0] & 1;
  }

  function pack(r, p) {
    var tx = gf(), ty = gf(), zi = gf();
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
  }

  function scalarmult(p, q, s) {
    var b, i;
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (i = 255; i >= 0; i--) {
      b = (s[(i / 8) | 0] >> (i & 7)) & 1;
      cswap(p, q, b);
      add(q, p);
      cadd(p, p);
      cswap(p, q, b);
    }
  }

  function scalarbase(p, s) {
    var q = [gf(), gf(), gf(), gf()];
    set25519(q[0], gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]));
    set25519(q[1], gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]));
    set25519(q[2], gf1);
    M(q[3], q[0], q[1]);
    scalarmult(p, q, s);
  }

  function set25519(r, a) { for (var i = 0; i < 16; i++) r[i] = a[i]; }
  function cswap(p, q, b) {
    for (var i = 0; i < 4; i++) sel25519(p[i], q[i], b);
  }
  function add(p, q) {
    var a = gf(), b = gf(), c = gf(), d = gf(), t = gf(), e = gf(), f = gf(), g = gf(), h = gf();
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[1], p[0]);
    A(t, q[1], q[0]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);
    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
  }
  function cadd(p, q) { add(p, q); }

  function reduce(a) {
    var x = new Float64Array(64);
    for (var i = 0; i < 64; i++) x[i] = a[i];
    for (var i = 0; i < 64; i++) a[i] = 0;
    modL(a, x);
  }

  var L = new Float64Array([
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd0, 0x9e, 0x26, 0x41, 0x72, 0x3f, 0x42, 0xef,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
  ]);

  function modL(r, x) {
    var carry, i, j, k;
    for (i = 63; i >= 32; i--) {
      carry = 0;
      for (j = i - 32, k = i - 12; j < k; ++j) {
        x[j] += carry - 16 * x[i] * L[j - (i - 32)];
        carry = (x[j] + 128) >> 8;
        x[j] -= carry * 256;
      }
      x[j] += carry;
      x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
      x[j] += carry - (x[31] >> 4) * L[j];
      carry = x[j] >> 8;
      x[j] &= 255;
    }
    for (j = 0; j < 32; j++) {
      x[j] -= carry * L[j];
      if (j < 31) {
        x[j + 1] += x[j] >> 8;
        x[j] &= 255;
      }
    }
    for (i = 0; i < 32; i++) r[i] = x[i];
  }

  function ed25519Verify(msgBytes, sigBytes, pkBytes) {
    if (sigBytes.length !== 64 || pkBytes.length !== 32) return false;
    return crypto_sign_verify_detached(sigBytes, msgBytes, pkBytes) === 0;
  }

  // -------------------------------------------------------------------------
  // Encoding helpers
  // -------------------------------------------------------------------------
  function utf8ToBytes(str) {
    if (typeof TextEncoder !== "undefined") {
      return new TextEncoder().encode(str);
    }
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i);
      if (code < 0x80) {
        bytes.push(code);
      } else if (code < 0x800) {
        bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
      } else if (code < 0xd800 || code >= 0xe000) {
        bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      } else {
        i++;
        var code2 = str.charCodeAt(i);
        var cp = 0x10000 + (((code & 0x3ff) << 10) | (code2 & 0x3ff));
        bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      }
    }
    return new Uint8Array(bytes);
  }

  function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
      var h = bytes[i].toString(16);
      hex.push(h.length === 1 ? "0" + h : h);
    }
    return hex.join("");
  }

  function hexToBytes(hex) {
    hex = hex.replace(/\s+/g, "");
    if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function base64UrlToBytes(b64url) {
    var b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    var raw = (typeof atob !== "undefined") ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    return bytes;
  }

  function bytesToBase64Url(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    var b64 = (typeof btoa !== "undefined") ? btoa(bin) : Buffer.from(bin, "binary").toString("base64");
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // -------------------------------------------------------------------------
  // SPKI PEM / DER Parser for Ed25519
  // -------------------------------------------------------------------------
  var ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100";

  function parseSpkiPem(pemStr) {
    var lines = pemStr.trim().split(/\r?\n/);
    var b64 = lines.filter(function(l) { return !l.startsWith("---"); }).join("");
    var der = (typeof atob !== "undefined") ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
    var derBytes = new Uint8Array(der.length);
    for (var i = 0; i < der.length; i++) derBytes[i] = der.charCodeAt(i);

    var derHex = bytesToHex(derBytes);
    var fingerprint = "sha256:" + sha256Hex(derBytes);

    if (derBytes.length === 44 && derHex.startsWith(ED25519_SPKI_PREFIX_HEX)) {
      var rawPubBytes = derBytes.subarray(12);
      return {
        fingerprint: fingerprint,
        rawPublicKeyBytes: rawPubBytes,
        rawPublicKeyHex: bytesToHex(rawPubBytes),
        spkiDerBytes: derBytes
      };
    }
    throw new Error("Invalid Ed25519 SubjectPublicKeyInfo PEM");
  }

  function rawPublicKeyToSpki(rawPubBytes) {
    if (rawPubBytes.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
    var prefix = hexToBytes(ED25519_SPKI_PREFIX_HEX);
    var spki = new Uint8Array(44);
    spki.set(prefix, 0);
    spki.set(rawPubBytes, 12);
    return {
      spkiDerBytes: spki,
      fingerprint: "sha256:" + sha256Hex(spki),
      rawPublicKeyBytes: rawPubBytes,
      rawPublicKeyHex: bytesToHex(rawPubBytes)
    };
  }

  return {
    sha256: sha256,
    sha256Hex: sha256Hex,
    ed25519Verify: ed25519Verify,
    utf8ToBytes: utf8ToBytes,
    bytesToHex: bytesToHex,
    hexToBytes: hexToBytes,
    base64UrlToBytes: base64UrlToBytes,
    bytesToBase64Url: bytesToBase64Url,
    parseSpkiPem: parseSpkiPem,
    rawPublicKeyToSpki: rawPublicKeyToSpki
  };
}));

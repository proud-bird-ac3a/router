// x2_hash.js  — SHA-224 / MD5MD5 / base64Secret / UUID helpers
// 映射:  h0=sha224, h1=MD5MD5, h2=base64SecretEncode, h3=base64SecretDecode
//        h4=getUUIDBytes, h5=uuidMatch

// ──── UUID 缓存 + hexNibble ────
const _uc = new Map();                          // UUID字节缓存

function _hx(c) {                               // 读取十六进制半字节
  if (c >= 48 && c <= 57) return c - 48;
  c |= 32;
  if (c >= 97 && c <= 102) return c - 87;
  return -1;
}

function h4(k) {                                // 获取UUID字节
  const u = String(k ?? '');
  let z = _uc.get(u); if (z) return z;
  const e = u.replace(/-/g, '');
  if (e.length !== 32) return null;
  const y = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    const hi = _hx(e.charCodeAt(i * 2)), lo = _hx(e.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0) return null;
    y[i] = (hi << 4) | lo;
  }
  if (_uc.size >= 32) _uc.clear();
  _uc.set(u, y); return y;
}

function h5(d, o, k) {                          // UUID字节匹配
  const e = h4(k);
  if (!e || d.byteLength < o + 16) return false;
  for (let i = 0; i < 16; i++) if (d[o + i] !== e[i]) return false;
  return true;
}

// ──── SHA-224 (纯JS, 不依赖 WebCrypto) ────
function h0(s) {                                // sha224
  const _K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  const _R = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
  s = unescape(encodeURIComponent(s));
  const l = s.length * 8; s += String.fromCharCode(0x80);
  while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
  const _h = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
  const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
  s += String.fromCharCode((hi>>>24)&0xFF,(hi>>>16)&0xFF,(hi>>>8)&0xFF,hi&0xFF,(lo>>>24)&0xFF,(lo>>>16)&0xFF,(lo>>>8)&0xFF,lo&0xFF);
  const w = [];
  for (let i = 0; i < s.length; i += 4)
    w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
  for (let i = 0; i < w.length; i += 16) {
    const x = new Array(64).fill(0);
    for (let j = 0; j < 16; j++) x[j] = w[i + j];
    for (let j = 16; j < 64; j++) {
      const s0 = _R(x[j - 15], 7) ^ _R(x[j - 15], 18) ^ (x[j - 15] >>> 3);
      const s1 = _R(x[j - 2], 17) ^ _R(x[j - 2], 19) ^ (x[j - 2] >>> 10);
      x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, H] = _h;
    for (let j = 0; j < 64; j++) {
      const S1 = _R(e, 6) ^ _R(e, 11) ^ _R(e, 25), ch = (e & f) ^ (~e & g), t1 = (H + S1 + ch + _K[j] + x[j]) >>> 0;
      const S0 = _R(a, 2) ^ _R(a, 13) ^ _R(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
      H = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    const arr = [a, b, c, d, e, f, g, H];
    for (let j = 0; j < 8; j++) _h[j] = (_h[j] + arr[j]) >>> 0;
  }
  let hex = '';
  for (let i = 0; i < 7; i++)
    for (let j = 24; j >= 0; j -= 8)
      hex += ((_h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
  return hex;
}

// ──── MD5MD5 (WebCrypto MD5 double-hash) ────
async function h1(t) {                          // MD5MD5
  const e = new TextEncoder();
  const a1 = await crypto.subtle.digest('MD5', e.encode(t));
  const a1a = Array.from(new Uint8Array(a1));
  const x1 = a1a.map(b => b.toString(16).padStart(2, '0')).join('');
  const a2 = await crypto.subtle.digest('MD5', e.encode(x1.slice(7, 27)));
  const a2a = Array.from(new Uint8Array(a2));
  return a2a.map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

// ──── base64Secret 编解码 ────
function h2(p, k) {                             // base64SecretEncode
  const e = new TextEncoder();
  const d = e.encode(p), y = e.encode(k);
  const m = new Uint8Array(d.length);
  for (let i = 0; i < d.length; i++) m[i] = d[i] ^ y[i % y.length];
  let s = '';
  for (let i = 0; i < m.length; i++) s += String.fromCharCode(m[i]);
  return btoa(s);
}

function h3(q, k) {                             // base64SecretDecode
  const bin = atob(q);
  const m = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) m[i] = bin.charCodeAt(i);
  const e = new TextEncoder();
  const y = e.encode(k);
  const d = new Uint8Array(m.length);
  for (let i = 0; i < m.length; i++) d[i] = m[i] ^ y[i % y.length];
  return new TextDecoder().decode(d);
}

export { h0, h1, h2, h3, h4, h5 };

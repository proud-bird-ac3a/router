// x4_proto.js  — VLESS / Trojan / SS 协议解析
// 映射:  p0=parseVless, p1=parseTrojan, p3=detectProtocol, p4=isSpeedTest
// 依赖:  b0/b1/b2/b4 from x1_util,  h0/h1/h4/h5 from x2_hash

import { b0, b1, b2, b4 } from './x1_util.js';
import { h0, h4, h5 } from './x2_hash.js';

// ──── 共享解码器 ────
const _td = b4;  // TextDecoder (复用)

// ──── 地址解析 (共享) ────
function _a4(d, o) {          // IPv4解析
  return `${d[o]}.${d[o+1]}.${d[o+2]}.${d[o+3]}`;
}
function _a6(d, o) {          // IPv6解析
  const p = [];
  for (let i = 0; i < 8; i++) p.push(((d[o+i*2]<<8)|d[o+i*2+1]).toString(16));
  return p.join(':');
}
function _dm(d, o) {          // 域名解析
  const l = d[o];
  return { host: _td.decode(d.subarray(o+1, o+1+l)), next: o+1+l };
}

// ──── VLESS 解析 (p0) ────
function p0(c, k) {
  const d = b0(c);
  if (d.byteLength < 24) return { hasError: true, message: 'too short' };
  const v = d[0];
  if (!h5(d, 1, k)) return { hasError: true, message: 'bad uuid' };
  const ol = d[17], ci = 18 + ol;
  if (d.byteLength < ci + 4) return { hasError: true, message: 'too short' };
  const cmd = d[ci];
  if (cmd !== 1 && cmd !== 2) return { hasError: true, message: 'bad cmd' };
  const isU = cmd === 2;
  const pi = ci + 1;
  const port = (d[pi] << 8) | d[pi + 1];
  let ai = pi + 3, host = '';
  const at = d[pi + 2];
  switch (at) {
    case 1:
      if (d.byteLength < ai + 4) return { hasError: true, message: 'bad ipv4' };
      host = _a4(d, ai); ai += 4; break;
    case 2: {
      if (d.byteLength < ai + 1) return { hasError: true, message: 'bad domain len' };
      const r = _dm(d, ai); host = r.host; ai = r.next; break; }
    case 3:
      if (d.byteLength < ai + 16) return { hasError: true, message: 'bad ipv6' };
      host = _a6(d, ai); ai += 16; break;
    default: return { hasError: true, message: 'bad atype: ' + at };
  }
  if (!host) return { hasError: true, message: 'empty host' };
  return { hasError: false, at, port, host, isUDP: isU, rawData: d.subarray(ai), ver: v };
}

// ──── Trojan 解析 (p1) ────
function p1(c, pw) {
  const d = b0(c);
  const hx = h0(pw);                // SHA-224 of password
  if (d.byteLength < 58) return { hasError: true, message: 'too short' };
  if (d[56] !== 0x0d || d[57] !== 0x0a) return { hasError: true, message: 'bad header' };
  for (let i = 0; i < 56; i++)
    if (d[i] !== hx.charCodeAt(i)) return { hasError: true, message: 'bad password' };
  const si = 58;
  if (d.byteLength < si + 6) return { hasError: true, message: 'too short s5' };
  const cmd = d[si];
  if (cmd !== 1 && cmd !== 3) return { hasError: true, message: 'bad cmd' };
  const isU = cmd === 3;
  const at = d[si + 1];
  let ai = si + 2, host = '';
  switch (at) {
    case 1:
      if (d.byteLength < ai + 8) return { hasError: true, message: 'bad ipv4' };
      host = _a4(d, ai); ai += 4; break;
    case 3: {
      if (d.byteLength < ai + 1) return { hasError: true, message: 'bad domain len' };
      const r = _dm(d, ai); host = r.host; ai = r.next; break; }
    case 4:
      if (d.byteLength < ai + 20) return { hasError: true, message: 'bad ipv6' };
      host = _a6(d, ai); ai += 16; break;
    default: return { hasError: true, message: 'bad atype: ' + at };
  }
  if (!host) return { hasError: true, message: 'empty host' };
  if (d.byteLength < ai + 4) return { hasError: true, message: 'too short' };
  const port = (d[ai] << 8) | d[ai + 1];
  return { hasError: false, at, port, host, isUDP: isU, rawData: d.subarray(ai + 4) };
}

// ──── 快速协议检测 (p3) ────
function p3(d, k) {
  const v = b0(d);
  if (v.byteLength >= 18 && h5(v, 1, k)) return 'vless';
  if (v.byteLength >= 58 && v[56] === 0x0d && v[57] === 0x0a) {
    const hx = h0(k);
    let ok = true;
    for (let i = 0; i < 56; i++) if (v[i] !== hx.charCodeAt(i)) { ok = false; break; }
    if (ok) return 'trojan';
  }
  return null;
}

// ──── 测速域名检测 (p4) ────
const _sd = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];  // 'speed.cloudflare.com'
function p4(h) {
  for (const n of _sd) if (h === n || h.endsWith('.' + n)) return true;
  return false;
}

export { p0, p1, p3, p4 };

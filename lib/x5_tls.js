// s0_up.js — TCP/UDP forwarding + connection management
// 映射: u0=forwardTCP, u1=forwardUDP, u2=connectStreams, u3=dohQuery, u7=createTCPConnector
import { b0, b1, b2, b3, b4, c0, c1, L0 } from '../lib/x1_util.js';
import { q1 } from '../lib/x3_queue.js';
import { p4 } from '../lib/x4_proto.js';
import { _d0, _p, _s5e, _s5g, _s5a, _s5p, _s5w, _p0, _p1, _p2, _f0, va, vb, vc } from '../lib/x0_cfg.js';

// ======================== u1: UDP forward ========================
async function u1(chunk, ws, respHdr, req) {
  const d = b0(chunk);
  const _TCP = u7(req);
  const sock = _TCP({ hostname: '8.8.4.4', port: 53 });
  let hdr = respHdr;
  const w = sock.writable.getWriter();
  await w.write(d); w.releaseLock();

  const _h = (raw) => {
    if (ws.readyState !== 1) return;
    if (hdr) { const r = new Uint8Array(hdr.length + raw.byteLength); r.set(hdr, 0); r.set(raw, hdr.length); c1(ws, r.buffer); hdr = null; }
    else c1(ws, raw);
  };

  let buf = new Uint8Array(0);
  const _r = sock.readable.getReader();
  try {
    while (true) {
      const { done, value } = await _r.read();
      if (done) break; if (!value?.byteLength) continue;
      const cur = b0(value);
      const m = b2(buf, cur); buf = m;
      let off = 0;
      while (off + 2 <= buf.byteLength) {
        const dnsLen = (buf[off]<<8)|buf[off+1];
        const end = off + 2 + dnsLen;
        if (end > buf.byteLength) break;
        _h(buf.subarray(off + 2, end)); off = end;
      }
      buf = buf.slice(off);
    }
  } catch (e) { L0('[UDP] fail: ' + (e?.message || e)); }
  finally { try { _r.releaseLock(); } catch (_) {} try { sock.close(); } catch (_) {} }
}

// ======================== u0: TCP forward ========================
async function u0(h, p, raw, ws, resp, rw, k, req) {
  L0('[TCP] ' + h + ':' + p + ' proxy:' + _p);
  const _TCP = u7(req);

  const _sendFirst = async (sk, d) => {
    if (!b1(d)) return;
    const w = sk.writable.getWriter(); try { await w.write(b0(d)); } finally { try { w.releaseLock(); } catch (_) {} }
  };

  const _dial = async (addr, port) => {
    const s = _TCP({ hostname: addr, port }); await s.opened; return s;
  };

  const _tryDirect = async () => {
    const sk = await _dial(h, p);
    await _sendFirst(sk, raw);
    rw.sock = sk;
    u2(sk, ws, resp, async () => {
      if (rw.sock !== sk) return;
      // Fallback to proxy
      try { await _tryProxy(); } catch { c0(ws); }
    });
  };

  const _tryProxy = async () => {
    if (!_p && !_s5e) { if (!_f0) { c0(ws); throw new Error('no proxy'); } return _tryDirect(); }
    if (_s5e) return _trySocks();
    // proxyIP mode
    const ips = _p1 || (await _resolve(_p));
    if (!ips?.length) { if (!_f0) throw new Error('no proxyIP resolved'); return _tryDirect(); }
    const idx = (_p2++) % ips.length;
    const [ip, port] = ips[idx];
    const sk = await _dial(ip, port || 443);
    await _sendFirst(sk, raw);
    rw.sock = sk;
    u2(sk, ws, resp, null);
  };

  const _trySocks = async () => {
    const type = _s5e;
    const addr = _s5p;
    if (!addr?.hostname) { c0(ws); throw new Error('no socks addr'); }
    const { y0 } = await import('../proxy/p0_s5.js');
    const { y1 } = await import('../proxy/p1_http.js');
    const { y2 } = await import('../proxy/p2_https.js');

    let sk;
    if (type === 'socks5') sk = await y0(h, p, raw, addr, _TCP);
    else if (type === 'http') sk = await y1(h, p, raw, addr, false, _TCP);
    else if (type === 'https') sk = await y2(h, p, raw, addr, _TCP);
    else throw new Error('unknown socks type: ' + type);

    rw.sock = sk;
    u2(sk, ws, resp, null);
  };

  rw.retry = async () => _tryProxy();

  try {
    if (_s5e && (_s5g || _s5w?.some(w => new RegExp('^' + w.replace(/\*/g, '.*') + '$', 'i').test(h)))) {
      await _trySocks();
    } else {
      await _tryDirect();
    }
  } catch (e) { L0('[TCP] fail: ' + (e?.message || e)); throw e; }
}

// ======================== u2: connect streams ========================
async function u2(rs, ws, hd, retryFn) {
  const _dg = q1(ws, hd);
  let _r, _byob = false, _has = false;
  try { _r = rs.readable.getReader({ mode: 'byob' }); _byob = true; }
  catch { _r = rs.readable.getReader(); }

  try {
    if (!_byob) {
      while (true) {
        const { done, value } = await _r.read();
        if (done) break; if (!value?.byteLength) continue;
        _has = true; await _dg.send(value);
      }
    } else {
      let buf = new ArrayBuffer(65536);
      while (true) {
        const { done, value } = await _r.read(new Uint8Array(buf, 0, 65536));
        if (done) break; if (!value?.byteLength) continue;
        _has = true;
        if (value.byteLength >= 32768) { await _dg.flush(); await _dg.sendDirect(value); buf = new ArrayBuffer(65536); }
        else { await _dg.send(value); buf = value.buffer.byteLength >= 65536 ? value.buffer : new ArrayBuffer(65536); }
      }
    }
    await _dg.flush();
  } catch { c0(ws); }
  finally { try { _r.cancel(); } catch (_) {} try { _r.releaseLock(); } catch (_) {} }
  if (!_has && retryFn) await retryFn();
}

// ======================== u3: DoH query ========================
async function u3(domain, type, server = 'https://cloudflare-dns.com/dns-query') {
  const tmap = { A:1, AAAA:28, TXT:16 };
  const qt = tmap[type?.toUpperCase()] || 1;
  const labels = (domain.endsWith('.') ? domain.slice(0,-1) : domain).split('.');
  const qn = b2(...labels.map(l => { const e = b3.encode(l); return b2(new Uint8Array([e.length]), e); }), new Uint8Array([0]));
  const q = new Uint8Array(12 + qn.length + 4);
  new DataView(q.buffer).setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
  q[2] = 1; q[5] = 1; q.set(qn, 12);
  new DataView(q.buffer).setUint16(12 + qn.length, qt);
  new DataView(q.buffer).setUint16(14 + qn.length, 1);
  const r = await fetch(server, { method:'POST', headers:{'Content-Type':'application/dns-message','Accept':'application/dns-message'}, body:q });
  if (!r.ok) return [];
  const buf = new Uint8Array(await r.arrayBuffer());
  const an = (buf[6]<<8)|buf[7];
  const res = [];
  let off = 12;
  for (let i = 0; i < ((buf[4]<<8)|buf[5]); i++) {
    while (off < buf.length) { const l = buf[off]; if (l === 0) { off++; break; } if ((l & 0xC0) === 0xC0) { off += 2; break; } off += l + 1; }
    off += 4;
  }
  for (let i = 0; i < an && off < buf.length; i++) {
    while (off < buf.length) { const l = buf[off]; if (l === 0) { off++; break; } if ((l & 0xC0) === 0xC0) { off += 2; break; } off += l + 1; }
    const at = (buf[off]<<8)|buf[off+1]; off += 8;
    const rl = (buf[off]<<8)|buf[off+1]; off += 2;
    const rd = buf.subarray(off, off + rl); off += rl;
    if (at === 1 && rl === 4) res.push(rd[0]+'.'+rd[1]+'.'+rd[2]+'.'+rd[3]);
    else if (at === 28 && rl === 16) { const s=[]; for(let j=0;j<16;j+=2)s.push(((rd[j]<<8)|rd[j+1]).toString(16)); res.push(s.join(':')); }
  }
  return res;
}

// ======================== u7: TCP connector ========================
function u7(req) {
  const f = req?.fetcher;
  if (!f || typeof f.connect !== 'function') throw new Error('connect unavailable');
  return (o,i) => i === undefined ? f.connect(o) : f.connect(o,i);
}

// ======================== _resolve: resolve proxyIP ========================
let _rc = null;
async function _resolve(host) {
  if (_rc) return _rc;
  _rc = (async () => {
    const ips = await u3(host, 'A');
    return ips.map(ip => [ip, 443]);
  })();
  return _rc;
}

export { u0, u1, u2, u3, u7 };

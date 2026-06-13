// x3_queue.js  — 上行写入队列 + 下行Grain发送器
// 映射:  q0=createUploadQueue, q1=createDownGrain
// 依赖:  b0/b1/b2/c0 from x1_util,  v2/v3/v4/v5/v5t/v6 from x0_cfg

import { b0, b1, b2, c0, L0 } from './x1_util.js';
import { v2, v3, v4, v5, v5t, v6 } from './x0_cfg.js';

// ──── 上行写入队列 (合并小chunk, 防溢出, 支持重试) ────
function q0({ getWriter, releaseWriter, retryConnect, onClose, name = 'up' }) {
  // ============= _Q0 内部状态 =============
  let a = [], g = 0, z = 0, _r = false, _c = false;
  let _b = null, _w = [], _x = null, _p = Promise.resolve();

  const _s = (cs, err) => { if (cs) for (const c of cs) err ? c.reject(err) : c.resolve(); };
  const _n = () => { if (g > 32 && g * 2 >= a.length) { a = a.slice(g); g = 0; } };
  const _y = () => { if (!z && !_r && _w.length) { const ws = _w; _w = []; for (const r of ws) r(); } };
  const _q = (err) => {
    const e = err ?? (_c ? new Error(name + ': closed') : null);
    if (e) { _s(_x, e); _x = null; }
    a = []; g = 0; z = 0; _y();
  };
  const _h = () => {
    if (g >= a.length) return null;
    const it = a[g]; a[g++] = undefined;
    z -= it.chunk.byteLength; _n(); return it;
  };
  const _k = () => {
    const f = _h(); if (!f) return null;
    if (g >= a.length || f.chunk.byteLength >= v2) return f;
    let n = f.chunk.byteLength, e = g, rt = f.allowRetry, cs = f.completions ?? null;
    while (e < a.length) {
      const nxt = a[e];
      if (n + nxt.chunk.byteLength > v2) break;
      n += nxt.chunk.byteLength; rt = rt && nxt.allowRetry;
      if (nxt.completions) cs = cs ? cs.concat(nxt.completions) : nxt.completions;
      e++;
    }
    if (e === g) return f;
    const out = (_b ??= new Uint8Array(v2));
    out.set(f.chunk); let off = f.chunk.byteLength;
    while (g < e) { const nxt = a[g]; a[g++] = undefined; z -= nxt.chunk.byteLength; out.set(nxt.chunk, off); off += nxt.chunk.byteLength; }
    _n(); return { chunk: out.subarray(0, n), allowRetry: rt, completions: cs };
  };

  const _d = async () => {
    if (_r || _c) return; _r = true;
    let errOnce = false;
    try {
      let w = null;
      while (!_c) {
        const it = _k(); if (!it) break;
        w = getWriter(); if (!w) throw new Error(name + ': writer unavailable');
        const cs = it.completions ?? null; _x = cs;
        try {
          await w.write(it.chunk);
        } catch (e) {
          releaseWriter?.();
          if (!it.allowRetry || typeof retryConnect !== 'function') throw e;
          await retryConnect(); w = getWriter(); if (!w) throw e;
          await w.write(it.chunk);
        }
        _s(cs);
      }
    } catch (e) {
      _c = true; _q(e); errOnce = true;
      L0('[' + name + '] fail: ' + (e?.message ?? e));
      try { onClose?.(e); } catch (_) {}
    } finally {
      _r = false; if (_x === _x) _x = null;
      if (!_c && g < a.length) queueMicrotask(_d);
      else _y();
    }
  };

  const _j = (data, allowRetry = true, waitFlush = false) => {
    if (_c) return false;
    const chunk = b0(data);
    if (!chunk.byteLength) return true;
    const nb = z + chunk.byteLength, ni = a.length - g + 1;
    if (nb > v3 || ni > v4) {
      _c = true;
      const e = Object.assign(new Error(name + ': overflow ' + nb + 'B/' + ni), { isQueueOverflow: true });
      _q(e); try { onClose?.(e); } catch (_) {} throw e;
    }
    let p = null, cs = null;
    if (waitFlush) { cs = []; p = new Promise((r, j) => cs.push({ resolve: r, reject: j })); }
    a.push({ chunk, allowRetry, completions: cs }); z = nb;
    if (!_r) queueMicrotask(_d);
    return waitFlush ? p.then(() => true) : true;
  };

  return {
    write(data, allowRetry) { return _j(data, allowRetry, false); },
    writeAndWait(data, allowRetry) { return _j(data, allowRetry, true); },
    waitIdle() { if (z || _r) return new Promise(r => _w.push(r)); },
    flush() { _c = true; _q(); },
    get ready() { return !_c && !_r; }
  };
}

// ──── 下行Grain发送器 (聚块 + 静默超时刷新) ────
function q1(ws, hd = null) {
  const cap = v5, tail = v5t, low = Math.max(4096, tail << 3);
  let hdr = hd, buf = new Uint8Array(cap), pos = 0, _t = null, _m = false, _g = 0, _s = 0, _w = 0, _f = null;

  const _send = async (c) => {
    if (ws.readyState !== 1) throw new Error('ws closed');
    const sendResult = ws.send(c);
    if (sendResult && typeof sendResult.then === 'function') await sendResult;
  };
  const _at = (c) => {
    if (!hdr) return c;
    const m = new Uint8Array(hdr.length + c.byteLength);
    m.set(hdr, 0); m.set(c, hdr.length); hdr = null; return m;
  };
  const _flush = async () => {
    while (_f) await _f;
    if (_t) clearTimeout(_t); _t = null; _m = false;
    if (!pos) return;
    const out = buf.subarray(0, pos).slice(); buf = new Uint8Array(cap); pos = 0; _w = 0;
    _f = _send(out).finally(() => { _f = null; });
    return _f;
  };
  const _sc = () => {
    if (_t || _m) return; _m = true; _s = _g;
    queueMicrotask(() => {
      _m = false; if (!pos || _t) return;
      if (cap - pos < tail) { _flush().catch(() => c0(ws)); return; }
      _t = setTimeout(() => {
        _t = null; if (!pos) return;
        if (cap - pos < tail) { _flush().catch(() => c0(ws)); return; }
        if (_w < 2 && (_g !== _s || pos < low)) { _w++; _s = _g; _sc(); return; }
        _flush().catch(() => c0(ws));
      }, Math.max(v6, 1));
    });
  };

  return {
    async sendDirect(data) {
      let c = b0(data); if (!c.byteLength) return;
      c = _at(c); await _send(c);
    },
    async send(data) {
      let c = b0(data); if (!c.byteLength) return;
      c = _at(c);
      let off = 0, total = c.byteLength;
      while (off < total) {
        if (!pos && total - off >= cap) {
          const n = Math.min(cap, total - off);
          await _send(off || n !== total ? c.subarray(off, off + n) : c);
          off += n; continue;
        }
        const n = Math.min(cap - pos, total - off);
        buf.set(c.subarray(off, off + n), pos); pos += n; off += n; _g++;
        if (pos === cap || cap - pos < tail) await _flush();
        else _sc();
      }
    },
    flush: _flush
  };
}

export { q0, q1 };

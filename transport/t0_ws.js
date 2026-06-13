// t0_ws.js — WebSocket transport bridge
// 映射: w0=handleWS, w1=decodeWSEarlyData
import { b0, b1, b2, c0, c1, L0 } from '../lib/x1_util.js';
import { q0, q1 } from '../lib/x3_queue.js';
import { p0 as p0_VL, p1 as p1_TR, p3, p4 } from '../lib/x4_proto.js';
import { h5 } from '../lib/x2_hash.js';
import { _d0, v1, v1h } from '../lib/x0_cfg.js';

// ======================== w0: WebSocket handler ========================
async function w0(req, k, url) {
  const _wp = new WebSocketPair();
  const [_cl, _sv] = Object.values(_wp);
  try { _sv.accept({ allowHalfOpen: true }); } catch (_) { _sv.accept(); }
  _sv.binaryType = 'arraybuffer';

  const _rw = { sock: null, _cp: null, retry: null, _tc: { cache: new Uint8Array(0) } };
  let _isD = false, _isT = null, _pt = null, _s = null, _w = null, _uq = null;
  let _c = false;
  const _doClose = () => { if (_c) return; _c = true; _uq?.flush(); _relW(); try { _rw.sock?.close(); } catch (_) {} c0(_sv); };

  const _relW = () => { if (_w) { try { _w.releaseLock(); } catch (_) {} _w = null; } _s = null; };
  const _getW = () => {
    const sk = _rw.sock; if (!sk) return null;
    if (sk !== _s) { _relW(); _s = sk; _w = sk.writable.getWriter(); }
    return _w;
  };

  _uq = q0({ getWriter: _getW, releaseWriter: _relW,
    retryConnect: async () => { if (typeof _rw.retry === 'function') await _rw.retry(); },
    onClose: _doClose, name: 'WS-up'
  });

  const _wr = async (c, rt = true) => _uq.writeAndWait(c, rt);

  // Protocol dispatch on first packet
  const _first = async (chunk) => {
    const d = b0(chunk);
    if (_isT) {
      const r = p1_TR(d, k);
      if (r?.hasError) throw new Error(r.message || 'bad trojan');
      const { port, host, isUDP: u, rawData: raw } = r;
      L0('[WS] trojan ' + host + ':' + port + ' UDP:' + u);
      if (p4(host)) throw new Error('speedtest blocked');
      if (u) { _isD = true; if (b1(raw) > 0) await _fwdU(raw, k); }
      else await _fwdT(host, port, raw, new Uint8Array([d[0], 0]));
    } else {
      const r = p0_VL(d, k);
      if (r?.hasError) throw new Error(r.message || 'bad vless');
      const { port, host, isUDP: u, rawData: raw, ver } = r;
      L0('[WS] vless ' + host + ':' + port + ' UDP:' + u);
      if (u) { if (port !== 53) throw new Error('UDP only port 53'); _isD = true; }
      const resp = new Uint8Array([ver, 0]);
      c1(_sv, resp.buffer);
      if (_isD) await _fwdU(raw, k);
      else await _fwdT(host, port, raw, resp);
    }
  };

  // Deferred imports for forwardTCP/forwardUDP (circular dep avoidance)
  const _fwdT = async (h, p, r, resp) => {
    const { u0 } = await import('../services/s0_up.js');
    return u0(h, p, r, _sv, resp, _rw, k, req);
  };
  const _fwdU = async (c, k2) => {
    const { u1 } = await import('../services/s0_up.js');
    return u1(c, _sv, null, req);
  };

  // Message handler
  const _onMsg = async (e) => {
    if (_c) return;
    try {
      const d = b0(e.data); if (!d.byteLength) return;
      if (_isD) return _fwdU(d, k);

      if (_rw.sock) {
        if (!(await _wr(d))) throw new Error('remote not ready');
      } else if (_pt === null) {
        _pt = p3(d, k) || 'vless';
        _isT = _pt === 'trojan';
        L0('[WS] proto: ' + _pt);
        await _first(d);
      } else {
        await _first(d);
      }
    } catch (e2) { _doClose(); }
  };

  _sv.addEventListener('message', _onMsg);
  _sv.addEventListener('close', _doClose);
  _sv.addEventListener('error', _doClose);

  // Early data
  const _ed = req.headers.get('sec-websocket-protocol') || '';
  if (_ed && !url.searchParams.get('enc')) {
    try { const ed = w1(_ed, k); if (ed?.byteLength) _onMsg({ data: ed.buffer }); }
    catch { c0(_sv); }
  }

  return new Response(null, { status: 101, webSocket: _cl, headers: { 'Sec-WebSocket-Extensions': '' } });
}

// ======================== w1: early data decoder ========================
function w1(hdr, k) {
  if (!hdr || hdr.length > v1h) throw new Error('early too large');
  let bytes;
  try { bytes = Uint8Array.fromBase64(hdr, { alphabet: 'base64url' }); } catch { /* fall */ }
  if (!bytes) {
    let n = hdr.replace(/-/g, '+').replace(/_/g, '/');
    const pad = n.length % 4; if (pad) n += '='.repeat(4 - pad);
    try { const b = atob(n); bytes = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) bytes[i] = b.charCodeAt(i); }
    catch { return null; }
  }
  if (bytes.byteLength > v1) throw new Error('early too large');
  return (bytes.byteLength >= 18 && h5(bytes, 1, k)) ? bytes : null;
}

export { w0, w1 };

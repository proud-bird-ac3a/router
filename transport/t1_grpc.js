// t1_grpc.js — gRPC bidirectional stream transport
// 映射: w2=handleGRPC
import { b0, b1, b2, c0, L0 } from '../lib/x1_util.js';
import { q0 } from '../lib/x3_queue.js';
import { p0 as p0_VL, p1 as p1_TR, p4 } from '../lib/x4_proto.js';
import { v2, v3, v4, v5, v5t, v6 } from '../lib/x0_cfg.js';

async function w2(req, k) {
  if (!req.body) return new Response('Bad Request', { status: 400 });
  const _r = req.body.getReader();
  const _rw = { sock: null, _cp: null, retry: null };
  const _tc = { cache: new Uint8Array(0) };
  let _isD = false, _isT = null, _s = null, _w = null, _uq = null;
  const _cap = v5, _iv = Math.max(v6, 1);

  const _hdr = new Headers({ 'Content-Type': 'application/grpc', 'grpc-status': '0', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' });

  return new Response(new ReadableStream({
    async start(ctlr) {
      let _c = false, _sq = [], _qb = 0, _t = null, _mq = false;

      const _gb = {
        readyState: 1,
        send(d) {
          if (_c) return;
          const chunk = b0(d);
          const lbs = [];
          let rem = chunk.byteLength >>> 0;
          while (rem > 127) { lbs.push((rem & 0x7f) | 0x80); rem >>>= 7; }
          lbs.push(rem);
          const pl = 1 + lbs.length + chunk.byteLength;
          const f = new Uint8Array(5 + pl);
          f[0] = 0; f[1] = (pl>>>24)&0xff; f[2] = (pl>>>16)&0xff; f[3] = (pl>>>8)&0xff; f[4] = pl&0xff;
          f[5] = 0x0a; f.set(new Uint8Array(lbs), 6);
          f.set(chunk, 6 + lbs.length);
          _sq.push(f); _qb += f.byteLength; _sc();
        },
        close() { if (_c) return; _flush(true); _c = true; this.readyState = 3; try { ctlr.close(); } catch (_) {} }
      };

      const _flush = (force = false) => {
        _mq = false; if (_t) { clearTimeout(_t); _t = null; }
        if (_c && !force) return; if (!_qb) return;
        const out = new Uint8Array(_qb);
        let off = 0;
        for (const item of _sq) { out.set(item, off); off += item.byteLength; }
        _sq = []; _qb = 0;
        try { ctlr.enqueue(out); } catch { _c = true; _gb.readyState = 3; }
      };

      const _sc = () => {
        if (_qb >= _cap) { _flush(); return; }
        if (_mq || _t) return; _mq = true;
        queueMicrotask(() => { _mq = false; if (_c || !_qb || _t) return; _t = setTimeout(_flush, _iv); });
      };

      const _relW = () => { if (_w) { try { _w.releaseLock(); } catch (_) {} _w = null; } _s = null; };
      const _getW = () => {
        const sk = _rw.sock; if (!sk) return null;
        if (sk !== _s) { _relW(); _s = sk; _w = sk.writable.getWriter(); }
        return _w;
      };

      const _doClose = () => {
        if (_c) return; _uq?.flush(); _flush(true); _c = true; _gb.readyState = 3;
        if (_t) clearTimeout(_t); _relW();
        try { _r.releaseLock(); } catch (_) {}
        try { _rw.sock?.close(); } catch (_) {}
        try { ctlr.close(); } catch (_) {}
      };

      _uq = q0({ getWriter: _getW, releaseWriter: _relW,
        retryConnect: async () => { if (typeof _rw.retry === 'function') await _rw.retry(); },
        onClose: _doClose, name: 'gRPC-up'
      });

      const _wr = async (p, rt = true) => _uq.writeAndWait(p, rt);

      // Deferred imports for protocol handling
      const _fwdT = async (h, p, raw, resp) => { const { u0 } = await import('../services/s0_up.js'); return u0(h, p, raw, _gb, resp, _rw, k, req); };
      const _fwdU = async (chunk) => { const { u1 } = await import('../services/s0_up.js'); return u1(chunk, _gb, null, req); };
      const _tud = async (c,w,ctx,r) => { const { w4 } = await import('../transport/t0_ws.js'); return w4 ? w4(c,w,ctx,r) : null; };

      try {
        let pending = new Uint8Array(0);
        while (true) {
          const { done, value } = await _r.read();
          if (done) break; if (!value || !value.byteLength) continue;
          const cur = b0(value);
          const merged = new Uint8Array(pending.length + cur.length);
          merged.set(pending, 0); merged.set(cur, pending.length); pending = merged;

          while (pending.byteLength >= 5) {
            const grpcLen = ((pending[1]<<24)>>>0) | (pending[2]<<16) | (pending[3]<<8) | pending[4];
            const fSize = 5 + grpcLen;
            if (pending.byteLength < fSize) break;
            let pl = pending.subarray(5, fSize);
            pending = pending.slice(fSize);
            if (!pl.byteLength) continue;

            // Strip protobuf varint length prefix
            if (pl.byteLength >= 2 && pl[0] === 0x0a) {
              let off = 1, found = false;
              while (off < pl.length) { if ((pl[off++] & 0x80) === 0) { found = true; break; } }
              if (found) pl = pl.subarray(off);
            }
            if (!pl.byteLength) continue;

            if (_isD) {
              if (_isT) await _tud(pl, _gb, _tc, req);
              else await _fwdU(pl);
              continue;
            }

            if (_rw.sock) {
              if (!(await _wr(pl))) throw new Error('remote not ready');
            } else {
              const first = b0(pl);
              if (_isT === null) _isT = first.byteLength >= 58 && first[56] === 0x0d && first[57] === 0x0a;

              if (_isT) {
                const r = p1_TR(first, k);
                if (r?.hasError) throw new Error(r.message || 'bad trojan');
                const { port, host, isUDP: u, rawData: raw } = r;
                L0('[gRPC] trojan ' + host + ':' + port + ' UDP:' + u);
                if (p4(host)) throw new Error('speedtest blocked');
                if (u) { _isD = true; if (b1(raw) > 0) await _tud(raw, _gb, _tc, req); }
                else await _fwdT(host, port, raw, null);
              } else {
                _isT = false;
                const r = p0_VL(first, k);
                if (r?.hasError) throw new Error(r.message || 'bad vless');
                const { port, host, ver, isUDP: u, rawData: raw } = r;
                L0('[gRPC] vless ' + host + ':' + port + ' UDP:' + u);
                if (u) { if (port !== 53) throw new Error('UDP only 53'); _isD = true; }
                _gb.send(new Uint8Array([ver, 0]));
                if (_isD) await _fwdU(raw);
                else await _fwdT(host, port, raw, null);
              }
            }
          }
          _flush();
        }
        await _uq.waitIdle();
      } catch (e) { L0('[gRPC] fail: ' + (e?.message || e)); }
      finally { _doClose(); }
    },
    cancel() { _uq?.flush(); try { _rw.sock?.close(); } catch (_) {} _relW(); try { _r.releaseLock(); } catch (_) {} }
  }), { status: 200, headers: _hdr });
}

export { w2 };

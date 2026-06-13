// t2_xhttp.js — XHTTP stream transport
// 映射: w3=handleXHTTP, w4=readXHTTPFirstPacket
import { b0, b1, b2, b4, c0, L0 } from '../lib/x1_util.js';
import { q0 } from '../lib/x3_queue.js';
import { p0 as p0_VL, p1 as p1_TR, p4 } from '../lib/x4_proto.js';
import { h0, h5 } from '../lib/x2_hash.js';
import { v2, v3, v4 } from '../lib/x0_cfg.js';

const _td = b4;

// ======================== w3: XHTTP stream handler ========================
async function w3(req, k) {
  if (!req.body) return new Response('Bad Request', { status: 400 });
  const _r = req.body.getReader();
  const _fp = await w4(_r, k);
  if (!_fp) { try { _r.releaseLock(); } catch (_) {} return new Response('Invalid', { status: 400 }); }
  if (p4(_fp.host)) { try { _r.releaseLock(); } catch (_) {} return new Response('Forbidden', { status: 403 }); }
  if (_fp.isU && _fp.proto !== 'trojan' && _fp.port !== 53) {
    try { _r.releaseLock(); } catch (_) {} return new Response('UDP not supported', { status: 400 });
  }

  const _rw = { sock: null, _cp: null, retry: null };
  const _tc = { cache: new Uint8Array(0) };
  let _s = null, _w = null, _uq = null, _uf = false;

  const _hdr = new Headers({ 'Content-Type': 'application/octet-stream', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' });

  return new Response(new ReadableStream({
    async start(ctlr) {
      let _c = false, _resp = _fp.resp ?? null;
      const _gb = {
        readyState: 1,
        send(d) { if (_c) return; try { ctlr.enqueue(d instanceof Uint8Array ? d : new Uint8Array(d)); } catch { _c = true; this.readyState = 3; } },
        close() { if (_c) return; _c = true; this.readyState = 3; try { ctlr.close(); } catch (_) {} }
      };

      const _relW = () => { if (_w) { try { _w.releaseLock(); } catch (_) {} _w = null; } _s = null; };
      const _getW = () => {
        const sk = _rw.sock; if (!sk) return null;
        if (sk !== _s) { _relW(); _s = sk; _w = sk.writable.getWriter(); }
        return _w;
      };

      const _doClose = () => {
        if (_c) return; _uq?.flush(); _c = true; _gb.readyState = 3;
        _relW(); try { _rw.sock?.close(); } catch (_) {}
        try { _r.releaseLock(); } catch (_) {}
        try { ctlr.close(); } catch (_) {}
      };

      _uq = q0({ getWriter: _getW, releaseWriter: _relW,
        retryConnect: async () => { if (typeof _rw.retry === 'function') await _rw.retry(); },
        onClose: _doClose, name: 'XHTTP-up'
      });

      const _wr = async (p, rt = true) => _uq.writeAndWait(p, rt);

      // Deferred imports
      const _fwdT = async (h, p, raw, resp) => { const { u0 } = await import('../services/s0_up.js'); return u0(h, p, raw, _gb, resp, _rw, k, req); };
      const _fwdU = async (chunk) => { const { u1 } = await import('../services/s0_up.js'); return u1(chunk, _gb, _resp, req); _resp = null; };
      const _tud = async (c, gb, ctx, r) => {
        const { w4: _w4 } = await import('../transport/t0_ws.js');
        // Trojan UDP forwarder — simplified inline
        const d = b0(c);
        const cached = ctx.cache instanceof Uint8Array ? ctx.cache : new Uint8Array(0);
        const input = cached.byteLength ? b2(cached, d) : d;
        let cur = 0;
        while (cur < input.byteLength) {
          const at = input[cur]; let ac = cur + 1, al = 0;
          if (at === 1) al = 4; else if (at === 4) al = 16;
          else if (at === 3) { if (input.byteLength < ac + 1) break; al = 1 + input[ac]; }
          else throw new Error('bad trojan udp atype: ' + at);
          const pc = ac + al;
          if (input.byteLength < pc + 6) break;
          const plen = (input[pc + 2] << 8) | input[pc + 3];
          if (input[pc + 4] !== 0x0d || input[pc + 5] !== 0x0a) throw new Error('bad delim');
          const ps = pc + 6, pe = ps + plen;
          if (input.byteLength < pe) break;
          const pkt = input.slice(ps, pe);
          cur = pe;
          if (!pkt.byteLength) continue;
          // Wrap DNS for TCP
          const tcpQ = pkt.byteLength < 2 || ((pkt[0]<<8)|pkt[1]) !== pkt.byteLength - 2
            ? b2(new Uint8Array([(pkt.byteLength>>>8)&0xff, pkt.byteLength&0xff]), pkt) : pkt;
          await _fwdU(tcpQ);
          _resp = null;
        }
        if (ctx) ctx.cache = input.slice(cur);
      };

      try {
        if (_fp.isU) {
          if (b1(_fp.raw) > 0) {
            if (_fp.proto === 'trojan') await _tud(_fp.raw, _gb, _tc, req);
            else await _fwdU(_fp.raw);
          }
        } else {
          await _fwdT(_fp.host, _fp.port, _fp.raw, _fp.resp);
        }

        while (true) {
          const { done, value } = await _r.read();
          if (done) break; if (!value || !value.byteLength) continue;
          if (_fp.isU) {
            if (_fp.proto === 'trojan') await _tud(value, _gb, _tc, req);
            else await _fwdU(value);
          } else {
            if (!(await _wr(value))) throw new Error('remote not ready');
          }
        }

        if (!_fp.isU) { await _uq.waitIdle(); const w2 = _getW(); if (w2) try { await w2.close(); } catch (_) {} }
      } catch (e) { L0('[XHTTP] fail: ' + (e?.message || e)); _doClose(); }
      finally { _uq?.flush(); _relW(); try { _r.releaseLock(); } catch (_) {} }
    },
    cancel() { _uq?.flush(); try { _rw.sock?.close(); } catch (_) {} _relW(); try { _r.releaseLock(); } catch (_) {} }
  }), { status: 200, headers: _hdr });
}

// ======================== w4: first packet reader ========================
async function w4(_r, k) {
  const _tryV = (d) => {
    if (d.byteLength < 24) return { s: 'more' };
    if (!h5(d, 1, k)) return { s: 'bad' };
    const ol = d[17], ci = 18 + ol;
    if (d.byteLength < ci + 4) return { s: 'more' };
    const cmd = d[ci];
    if (cmd !== 1 && cmd !== 2) return { s: 'bad' };
    const port = (d[ci+1]<<8)|d[ci+2];
    const at = d[ci+3];
    let ai = ci+4, host = '';
    if (at === 1) { if (d.byteLength < ai+4) return { s: 'more' }; host = d[ai]+'.'+d[ai+1]+'.'+d[ai+2]+'.'+d[ai+3]; ai+=4; }
    else if (at === 2) { if (d.byteLength < ai+1) return { s: 'more' }; const l = d[ai]; ai++; if (d.byteLength < ai+l) return { s: 'more' }; host = _td.decode(d.subarray(ai,ai+l)); ai+=l; }
    else if (at === 3) { if (d.byteLength < ai+16) return { s: 'more' }; const p=[]; for(let i=0;i<8;i++)p.push(((d[ai+i*2]<<8)|d[ai+i*2+1]).toString(16)); host=p.join(':'); ai+=16; }
    else return { s: 'bad' };
    if (!host) return { s: 'bad' };
    return { s: 'ok', r: { proto:'vless', host, port, isU:cmd===2, raw:d.subarray(ai), resp:new Uint8Array([d[0],0]) } };
  };

  const _tryT = (d) => {
    const hx = h0(k); const hb = new TextEncoder().encode(hx);
    if (d.byteLength < 58) return { s: 'more' };
    if (d[56]!==0x0d||d[57]!==0x0a) return { s: 'bad' };
    for (let i=0;i<56;i++) if (d[i]!==hb[i]) return { s: 'bad' };
    const cmd=d[58],isU=cmd===3;
    if (cmd!==1&&cmd!==3) return { s: 'bad' };
    const at=d[59];let ai=60,host='';
    if (at===1) { if(d.byteLength<ai+4)return { s:'more' }; host=d[ai]+'.'+d[ai+1]+'.'+d[ai+2]+'.'+d[ai+3]; ai+=4; }
    else if (at===3) { if(d.byteLength<ai+1)return { s:'more' }; const l=d[ai];ai++; if(d.byteLength<ai+l)return { s:'more' }; host=_td.decode(d.subarray(ai,ai+l)); ai+=l; }
    else if (at===4) { if(d.byteLength<ai+16)return { s:'more' }; const p=[];for(let i=0;i<8;i++)p.push(((d[ai+i*2]<<8)|d[ai+i*2+1]).toString(16));host=p.join(':');ai+=16; }
    else return { s:'bad' };
    if (!host) return { s:'bad' };
    if (d.byteLength<ai+4) return { s:'more' };
    const port=(d[ai]<<8)|d[ai+1];
    return { s:'ok', r:{ proto:'trojan',host,port,isU,raw:d.subarray(ai+4),resp:null } };
  };

  let buf = new Uint8Array(1024), off = 0;
  while (true) {
    const { value, done } = await _r.read();
    if (done) return off === 0 ? null : null;
    const chunk = b0(value);
    if (off + chunk.byteLength > buf.byteLength) {
      const nb = new Uint8Array(Math.max(buf.byteLength * 2, off + chunk.byteLength));
      nb.set(buf.subarray(0, off)); buf = nb;
    }
    buf.set(chunk, off); off += chunk.byteLength;
    const cur = buf.subarray(0, off);
    const tr = _tryT(cur); if (tr.s === 'ok') return { ...tr.r };
    const vl = _tryV(cur); if (vl.s === 'ok') return { ...vl.r };
    if (tr.s === 'bad' && vl.s === 'bad') return null;
  }
}

export { w3, w4 };

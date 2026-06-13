// p0_s5.js — SOCKS5 connect
import { b0, b2, b3, b1 } from '../lib/x1_util.js';

async function y0(h, p, raw, addr, _TCP) {
  const { username: u, password: pw, hostname: hn, port: pp } = addr;
  const sk = _TCP({ hostname: hn, port: pp });
  const _w = sk.writable.getWriter(), _r = sk.readable.getReader();
  try {
    const meth = u && pw ? new Uint8Array([5, 2, 0, 2]) : new Uint8Array([5, 1, 0]);
    await _w.write(meth);
    let rv = await _r.read();
    if (rv.done || rv.value.byteLength < 2) throw new Error('S5 method fail');
    const m = new Uint8Array(rv.value)[1];
    if (m === 2) {
      if (!u || !pw) throw new Error('S5 auth needed');
      const ub = b3.encode(u), pb = b3.encode(pw);
      await _w.write(new Uint8Array([1, ub.length, ...ub, pb.length, ...pb]));
      rv = await _r.read();
      if (rv.done || new Uint8Array(rv.value)[1] !== 0) throw new Error('S5 auth fail');
    } else if (m !== 0) throw new Error('S5 bad method: ' + m);
    const hb = b3.encode(h);
    await _w.write(new Uint8Array([5, 1, 0, 3, hb.length, ...hb, p >> 8, p & 0xff]));
    rv = await _r.read();
    if (rv.done || new Uint8Array(rv.value)[1] !== 0) throw new Error('S5 connect fail');
    if (b1(raw) > 0) await _w.write(b0(raw));
    _w.releaseLock(); _r.releaseLock();
    return sk;
  } catch (e) { try { _w.releaseLock(); } catch (_) {} try { _r.releaseLock(); } catch (_) {} try { sk.close(); } catch (_) {} throw e; }
}
export { y0 };

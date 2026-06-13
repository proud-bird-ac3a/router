// p1_http.js — HTTP CONNECT tunnel
import { b0, b2, b3, b4, b1 } from '../lib/x1_util.js';

async function y1(h, p, raw, addr, isTLS, _TCP) {
  const { username: u, password: pw, hostname: hn, port: pp } = addr;
  const sk = isTLS ? _TCP({ hostname: hn, port: pp }, { secureTransport: 'on', allowHalfOpen: false }) : _TCP({ hostname: hn, port: pp });
  const _w = sk.writable.getWriter(), _r = sk.readable.getReader();
  try {
    if (isTLS) await sk.opened;
    const auth = u && pw ? 'Proxy-Authorization: Basic ' + btoa(u + ':' + pw) + '\r\n' : '';
    const req = 'CONNECT ' + h + ':' + p + ' HTTP/1.1\r\nHost: ' + h + ':' + p + '\r\n' + auth + 'User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n';
    await _w.write(b3.encode(req)); _w.releaseLock();
    let buf = new Uint8Array(0), end = -1, rd = 0;
    while (end === -1 && rd < 8192) {
      const { done, value } = await _r.read();
      if (done || !value) throw new Error('proxy closed');
      buf = b2(buf, value); rd = buf.length;
      for (let i = 0; i < rd - 3; i++) if (buf[i]===0x0d&&buf[i+1]===0x0a&&buf[i+2]===0x0d&&buf[i+3]===0x0a) { end = i + 4; break; }
    }
    if (end === -1) throw new Error('CONNECT resp too long');
    const st = b4.decode(buf.subarray(0, end)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
    const code = st ? parseInt(st[1], 10) : NaN;
    if (!Number.isFinite(code) || code < 200 || code >= 300) throw new Error('CONNECT fail: ' + code);
    _r.releaseLock();
    if (b1(raw) > 0) { const w2 = sk.writable.getWriter(); await w2.write(b0(raw)); w2.releaseLock(); }
    if (rd > end) {
      const { readable, writable } = new TransformStream();
      const tw = writable.getWriter(); await tw.write(buf.subarray(end, rd)); tw.releaseLock();
      sk.readable.pipeTo(writable).catch(() => {});
      return { readable, writable: sk.writable, closed: sk.closed, close: () => sk.close() };
    }
    return sk;
  } catch (e) { try { _w.releaseLock(); } catch (_) {} try { _r.releaseLock(); } catch (_) {} try { sk.close(); } catch (_) {} throw e; }
}
export { y1 };

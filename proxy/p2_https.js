// p2_https.js — HTTPS CONNECT (TLS to proxy)
import { b0, b2, b3, b4, b1 } from '../lib/x1_util.js';
const _ip4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

async function y2(h, p, raw, addr, _TCP) {
  const { username: u, password: pw, hostname: hn, port: pp } = addr;
  const _isIP = _ip4.test(hn);
  const sni = _isIP ? '' : hn;
  const _tls = async (ac) => {
    const { T0 } = await import('../lib/x5_tls.js');
    const sk = _TCP({ hostname: hn, port: pp });
    try { await sk.opened; const t = new T0(sk, { serverName: sni, insecure: true, allowChacha: ac }); await t.handshake(); return t; }
    catch (e) { try { sk.close(); } catch (_) {} throw e; }
  };

  let tls;
  try { tls = await _tls(false); }
  catch (e) { if (!/cipher|handshake|TLS Alert|ServerHello/i.test(e?.message || '')) throw e; tls = await _tls(true); }

  try {
    const auth = u && pw ? 'Proxy-Authorization: Basic ' + btoa(u + ':' + pw) + '\r\n' : '';
    const req = 'CONNECT ' + h + ':' + p + ' HTTP/1.1\r\nHost: ' + h + ':' + p + '\r\n' + auth + 'User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n';
    await tls.write(b3.encode(req));
    let buf = new Uint8Array(0), end = -1, rd = 0;
    while (end === -1 && rd < 8192) {
      const v = await tls.read(); if (!v) throw new Error('proxy closed');
      buf = b2(buf, v); rd = buf.length;
      for (let i = 0; i < rd - 3; i++) if (buf[i]===0x0d&&buf[i+1]===0x0a&&buf[i+2]===0x0d&&buf[i+3]===0x0a) { end = i + 4; break; }
    }
    if (end === -1) throw new Error('CONNECT resp too long');
    const st = b4.decode(buf.subarray(0, end)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
    const code = st ? parseInt(st[1], 10) : NaN;
    if (!Number.isFinite(code) || code < 200 || code >= 300) throw new Error('CONNECT fail: ' + code);
    if (b1(raw) > 0) await tls.write(b0(raw));
    const extra = rd > end ? buf.subarray(end, rd) : null;
    let cs = false, rc, rj;
    const cP = new Promise((a, b) => { rc = a; rj = b; });
    const _settle = (fn, v) => { if (!cs) { cs = true; fn(v); } };
    const close = () => { try { tls.close(); } catch (_) {} _settle(rc); };
    const readable = new ReadableStream({
      async start(ctrl) {
        try {
          if (b1(extra) > 0) ctrl.enqueue(extra);
          while (true) { const d = await tls.read(); if (!d) break; if (d.byteLength > 0) ctrl.enqueue(d); }
          ctrl.close(); _settle(rc);
        } catch (e) { ctrl.error(e); _settle(rj, e); }
      }, cancel() { close(); }
    });
    const writable = new WritableStream({
      async write(c) { await tls.write(b0(c)); },
      close, abort(e) { close(); if (e) _settle(rj, e); }
    });
    return { readable, writable, closed: cP, close };
  } catch (e) { try { tls.close(); } catch (_) {} throw e; }
}
export { y2 };

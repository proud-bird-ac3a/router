// router.js — URL routing / dispatch
import { w0, w1 } from './transport/t0_ws.js';
import { w2 } from './transport/t1_grpc.js';
import { w3 } from './transport/t2_xhttp.js';
import { h1 } from './lib/x2_hash.js';
import { v7, v8 } from './lib/x0_cfg.js';

async function R0(req, env, ctx) {
  const _u = new URL(req.url);
  const _path = decodeURIComponent(_u.pathname).toLowerCase();
  const _ua = req.headers.get('user-agent') || '';
  const _up = (req.headers.get('upgrade') || '').toLowerCase();

  // --- Extract host / token ---
  const _host = _u.hostname;
  const _envUUID = env.UUID || '';
  let _k = _envUUID;

  // Check path-based UUID override
  const _pm = _path.match(/\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(\/|$)/i);
  if (_pm) _k = _pm[1];

  if (!_k) return new Response('No UUID configured', { status: 500 });

  // Collect env host config
  const _hosts = env.HOST ? String(env.HOST).replace(/[\t\"'\r\n]+/g, ',').replace(/,+/g, ',').replace(/^,|,$/g, '').split(',') : [];
  let _hostCfg = _u.hostname;
  if (env.PATH) _hostCfg += '/' + (env.PATH.startsWith('/') ? env.PATH.slice(1) : env.PATH);

  // --- Kill signature check ---
  if (req.headers.get(v7)) return new Response('', { status: 403 });
  if (_u.searchParams.get(v7)) return new Response('', { status: 403 });

  // --- Static pages ---
  if (_path === '/' || _path === '/index.html') {
    const r = await fetch(v8 + '/index.html'); if (r.ok) return r;
    return new Response('OK', { status: 200 });
  }
  if (_path === '/nginx') { const { g0n } = await import('./pages/g0_nginx.js'); return new Response(g0n(_hostCfg), { headers: { 'Content-Type': 'text/html;charset=utf-8' } }); }

  // --- Subscription routes ---
  if (_path === '/sub' || _path.startsWith('/sub/')) {
    const { z0, z1, z2 } = await import('./services/s1_sub.js');
    const target = _u.searchParams.get('target') || 'clash';
    const cfg = { host: _hostCfg, uuid: _k, path: env.PATH || '/', type: env.PROTOCOL || 'vless', transport: env.TRANSPORT || 'ws',
      sni: _u.hostname, fp: env.FINGERPRINT || 'chrome', hostname: _u.hostname, alpn: env.ALPN || 'h2,http/1.1',
      subname: env.SUBNAME || 'edgetunnel', ech: env.ECH || false };
    let body;
    if (target === 'clash') body = z0(cfg);
    else if (target === 'singbox') body = JSON.stringify(await z1(cfg), null, 2);
    else body = z2(cfg);
    return new Response(body, { headers: { 'Content-Type': target === 'clash' ? 'text/yaml' : 'text/plain;charset=utf-8' } });
  }

  // --- random IP generate ---
  if (_path === '/ip') {
    const { d1, d0 } = await import('./services/s3_isp.js');
    const [arr, txt] = await d1(req, 16, -1);
    return new Response(txt, { headers: { 'Content-Type': 'text/plain' } });
  }

  // --- Token-based auth page ---
  if (_path === '/' + await h1(_host + _k)) {
    const { s2_kv } = await import('./services/s2_kv.js');
    return new Response('Config page', { status: 200 }); // Simplified
  }

  // --- Transport routing ---
  const _tr = env.TRANSPORT || 'ws';
  const _proxy = { proxyIP: _u.searchParams.get('proxyip') || env.PROXYIP || '', fallback: true, proxyType: null, global: false, addr: {}, whitelist: null };

  if (_tr === 'ws' || _up === 'websocket') {
    return w0(req, _k, _u);
  }
  if (_tr === 'grpc' || _path.startsWith('/grpc')) {
    return w2(req, _k);
  }
  if (_tr === 'xhttp' || _path.startsWith('/xhttp')) {
    return w3(req, _k);
  }

  // Default: WebSocket
  return w0(req, _k, _u);
}

export { R0 };

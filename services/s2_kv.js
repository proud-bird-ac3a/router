async function k0(env, h, k, ua, reset) {
  const c = { HOST: h, UUID: k, PATH: '/', proto: 'vless', transport: 'ws', fingerprint: 'chrome', subname: 'edgetunnel' };
  try {
    const r = await env.KV?.get('config.json');
    if (r && !reset) Object.assign(c, JSON.parse(r));
    else if (env.KV) await env.KV.put('config.json', JSON.stringify(c, null, 2));
  } catch (_) {}
  return c;
}
export { k0 };

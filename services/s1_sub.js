function z0(c) { return 'proxies:\n  - name: ' + (c.subname||'node') + '\n    server: ' + c.hostname + '\n    port: 443\n    type: ' + (c.transport||'ws') + '\n    uuid: ' + c.uuid + '\n    network: ' + (c.transport||'ws'); }
async function z1(c) { return { outbounds: [{ type: c.transport||'ws', server: c.hostname, server_port: 443, uuid: c.uuid }] }; }
function z2(c) { return c.subname + ' = ' + c.transport + ', ' + c.hostname + ', 443, uuid=' + c.uuid; }
export { z0, z1, z2 };

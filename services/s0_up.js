// services/s0_up.js — TCP/UDP upstream forwarder
// 上行转发：本地 socket ↔ 远程代理 IP

import { s0e, _e0, _e1, _e2, _e3, _e4, _e5, _e6, _e7, _e8, _e9, _f0, _f1, _f2, _f3, _f4, _f5, _f6, _f7, _f8, _f9, _g0 } from '../lib/x0_cfg.js';
import { b0, b2, c0, L0 } from '../lib/x1_util.js';

// --- mutable state (local, not imported) ---
let _p2 = 0;  // UDP port rotation counter
let _p3 = {};  // address cache

// ===================================================================
// TCP forward: connect to proxy, bidirectional relay
// ===================================================================
export async function u0(ws, addr, proxyIP, port, protocol) {
  // protocol: 'vless' | 'trojan' | 'ss'
  // proxyIP: string (可以是逗号分隔的多个 IP)
  
  const ips = proxyIP ? proxyIP.split(',').map(s => s.trim()).filter(Boolean) : null;
  if (!ips || ips.length === 0) {
    L0('u0: no proxyIP');
    return false;
  }

  let connected = false;
  let remote = null;
  let lastErr = null;

  // try each IP in order (已在上层做过 race dial)
  for (const ip of ips) {
    try {
      remote = await connect(ip, port);
      if (remote) {
        connected = true;
        break;
      }
    } catch (e) {
      lastErr = e;
      L0('u0: connect fail', ip, port, e.message);
    }
  }

  if (!connected) {
    c0(ws);
    L0('u0: all IPs failed', lastErr?.message);
    return false;
  }

  // bidirectional relay
  const relay = async (reader, writer, label) => {
    try {
      const r = reader.getReader();
      const w = writer.getWriter();
      while (true) {
        const { done, value } = await r.read();
        if (done) break;
        await w.write(value);
      }
    } catch (e) {
      L0('u0: relay err', label, e.message);
    } finally {
      try { writer.close(); } catch(e) { /* ignore */ }
    }
  };

  // start both directions
  Promise.all([
    relay(ws.readable, remote.writable, 'ws→remote'),
    relay(remote.readable, ws.writable, 'remote→ws'),
  ]).finally(() => {
    c0(remote);
  });

  return true;
}

// ===================================================================
// UDP forward: local WebSocket ↔ remote UDP socket (length-prefixed)
// ===================================================================
export async function u1(ws, addr, proxyIP, protocol) {
  // UDP uses rotating port: _e0 ~ _e9 are 10 consecutive ports
  const udpPorts = [_e0, _e1, _e2, _e3, _e4, _e5, _e6, _e7, _e8, _e9];
  const ips = proxyIP ? proxyIP.split(',').map(s => s.trim()).filter(Boolean) : null;
  
  if (!ips || ips.length === 0) {
    L0('u1: no proxyIP for UDP');
    return false;
  }

  const idx = (_p2++) % ips.length;
  const ip = ips[idx];
  const port = udpPorts[idx % udpPorts.length];

  let udpSocket = null;
  try {
    udpSocket = new UDPSocket();
    await udpSocket.connect({ hostname: ip, port });
  } catch (e) {
    L0('u1: udp connect fail', ip, port, e.message);
    return false;
  }

  // WS → UDP: read length-prefixed datagrams, forward to UDP socket
  (async () => {
    try {
      const writer = udpSocket.writable.getWriter();
      const reader = ws.readable.getReader();
      let buf = new Uint8Array(0);

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buf = b2(buf, value);
        // read length-prefixed: 2 bytes big-endian length + payload
        while (buf.length >= 2) {
          const len = (buf[0] << 8) | buf[1];
          if (buf.length < 2 + len) break;
          const datagram = buf.slice(2, 2 + len);
          buf = buf.slice(2 + len);
          await writer.write(datagram);
        }
      }
    } catch (e) {
      L0('u1: ws→udp err', e.message);
    } finally {
      try { udpSocket.close(); } catch(e) {}
    }
  })();

  // UDP → WS: read datagrams, write length-prefixed to WS
  (async () => {
    try {
      const writer = ws.writable.getWriter();
      const reader = udpSocket.readable.getReader();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        // prepend 2-byte length
        const framed = new Uint8Array(2 + value.length);
        framed[0] = (value.length >> 8) & 0xFF;
        framed[1] = value.length & 0xFF;
        framed.set(value, 2);
        await writer.write(framed);
      }
    } catch (e) {
      L0('u1: udp→ws err', e.message);
    } finally {
      c0(ws);
    }
  })();

  return true;
}

// ===================================================================
// DoH (DNS over HTTPS) query
// ===================================================================
export async function u2(domain, type = 'A') {
  // DNS wire format query builder
  const buildDNSQuery = (name, qtype) => {
    const labels = name.split('.');
    let len = 12 + labels.reduce((s,l) => s + l.length + 1, 0) + 1 + 4;
    const buf = new Uint8Array(len);
    const dv = new DataView(buf.buffer);
    dv.setUint16(0, Math.floor(Math.random() * 65536)); // ID
    dv.setUint16(2, 0x0100); // flags: standard query
    dv.setUint16(4, 1);      // QDCOUNT
    dv.setUint16(6, 0);      // ANCOUNT
    dv.setUint16(8, 0);      // NSCOUNT
    dv.setUint16(10, 0);     // ARCOUNT
    let off = 12;
    for (const label of labels) {
      buf[off++] = label.length;
      for (let i = 0; i < label.length; i++) buf[off++] = label.charCodeAt(i);
    }
    buf[off++] = 0; // root label
    const qtypeMap = { A: 1, AAAA: 28, CNAME: 5, MX: 15, TXT: 16, NS: 2 };
    dv.setUint16(off, qtypeMap[qtype] || 1); off += 2;
    dv.setUint16(off, 1); // QCLASS IN
    return buf;
  };

  const dohURLs = [
    'https://cloudflare-dns.com/dns-query',
    'https://dns.google/dns-query',
  ];

  for (const url of dohURLs) {
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Accept': 'application/dns-message', 'Content-Type': 'application/dns-message' },
        body: buildDNSQuery(domain, type),
      });
      if (!resp.ok) continue;
      const buf = await resp.arrayBuffer();
      const dv = new DataView(buf);
      const ancount = dv.getUint16(6);
      let off = 12;
      // skip question
      while (dv.getUint8(off) !== 0) off += dv.getUint8(off) + 1;
      off += 5; // skip root + QTYPE + QCLASS
      // parse answers
      const ips = [];
      for (let i = 0; i < ancount; i++) {
        // skip name (pointer or label)
        if (dv.getUint8(off) >= 0xC0) { off += 2; }
        else { while (dv.getUint8(off) !== 0) off += dv.getUint8(off) + 1; off++; }
        const rtype = dv.getUint16(off + 2);
        const rdlength = dv.getUint16(off + 8);
        off += 10;
        if (rtype === 1 && rdlength === 4) { // A
          ips.push(`${dv.getUint8(off)}.${dv.getUint8(off+1)}.${dv.getUint8(off+2)}.${dv.getUint8(off+3)}`);
        } else if (rtype === 28 && rdlength === 16) { // AAAA
          let ip = '';
          for (let j = 0; j < 16; j += 2) ip += (j ? ':' : '') + dv.getUint16(off+j).toString(16);
          ips.push(ip);
        }
        off += rdlength;
      }
      return ips;
    } catch (e) {
      L0('u2: DoH query fail', url, e.message);
    }
  }
  return [];
}

// ===================================================================
// address cache helpers
// ===================================================================
export function u3(key, ip) {
  // set address cache
  if (ip) _p3[key] = ip;
  return _p3[key] || null;
}

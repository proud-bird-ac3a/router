// x0_cfg.js  — 全局配置 / 常量 / 运行时状态
// 映射: v0=Version, v1=WS_EARLY_DATA_MAX, v2=UP_BUNDLE_TARGET, v3/v4=队列上限
//       v5/v6=下行Grain, v7=KILL_SIG, v8=静态页, v9=代理默认端口, va=白名单
//       vb=TCP并发拨号, vc=预加载竞速, s0=SS加密套件

const v0 = '2026-06-13';
export { v0 as ver };

// ──── 运行时可变状态 ────
let _z = null;                  // config_JSON (主配置对象)
let _p = '';                    // 反代IP (proxyIP)
let _s5e = null;                // 启用SOCKS5反代 (socks5 enabled type)
let _s5g = false;               // 启用SOCKS5全局反代 (socks5 global flag)
let _s5a = '';                  // 我的SOCKS5账号 (socks5 account string)
let _s5p = {};                  // parsedSocks5Address (解析后的地址对象)
let _s5w = null;                // 缓存SOCKS5白名单
let _p0 = null;                 // 缓存反代IP (cached proxyIP)
let _p1 = null;                 // 缓存反代解析数组 (cached resolved array)
let _p2 = 0;                    // 缓存反代数组索引 (round-robin cursor)
let _f0 = true;                 // 启用反代兜底 (fallback enabled)
let _d0 = false;                // 调试日志打印 (debug log print)

// ──── 传输常量 ────
const v1 = 8 * 1024;                        // WS_EARLY_DATA_MAX (8KB)
const v1h = Math.ceil(v1 * 4 / 3) + 4;      // WS_EARLY_DATA_HEADER_MAX
const v2 = 16 * 1024;                        // UP_BUNDLE_TARGET (16KB)
const v3 = 16 * 1024 * 1024;                 // UP_QUEUE_MAX_BYTES (16MB)
const v4 = 4096;                             // UP_QUEUE_MAX_ITEMS
const v5 = 32 * 1024;                        // DOWN_GRAIN_BYTES (32KB)
const v5t = 512;                             // DOWN_GRAIN_TAIL (512B)
const v6 = 0;                                // DOWN_GRAIN_SILENCE_MS

let vb = 2;                                  // TCP_DIAL_CONCURRENT (并发拨号数)
let vc = false;                              // PRELOAD_RACE (预加载竞速)

// ──── SS AEAD ────
const s0a = 16;    // SSAEAD_TAG_LEN  (SSAEAD标签长度)
const s0b = 12;    // SS_NONCE_LEN    (SSNonce长度)
// SS子密钥信息: TextEncoder().encode('ss-subkey')
const _sk = new TextEncoder().encode('ss-subkey');
const s0e = new TextEncoder();
const s0d = new TextDecoder();
const _sm = new Map();   // SS主密钥缓存

const s0 = {              // SS支持加密配置
  'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
  'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

// ──── 反代 / 代理默认端口 ────
const v9 = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };
function f2(e) { return v9[String((e ?? '').toLowerCase())] ?? 80; }

// ──── 白名单 / 特征码 / 静态页 ────
const va = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const v7 = (globalThis.Proxy?.name + 'IP').toUpperCase();   // KILL_SIG
const v8 = 'https://edt-pages.github.io';                    // STATIC_PAGES

// ──── 正则 ────
const _ba = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;  // B64 check
const _ip = /^\[.*\]$/;                                                     // IPv6 bracket check

// ──── 导出 ────
export {          _z,         _p,        _s5e,       _s5g,      _s5a,       _s5p,       _s5w,
          _p0,     _p1,       _p2,       _f0,        _d0,
          v1,      v1h,       v2,        v3,         v4,         v5,         v5t,        v6,
          vb,      vc,
          s0a,     s0b,       _sk,       s0e,        s0d,        _sm,        s0,
          v9,      f2,
          va,      v7,        v8,
          _ba,     _ip };

// setters
export function Xv(n) { vb = n; }      // setTCPDialConcurrent
export function Xw(n) { vc = n; }      // setPreloadRaceDial
export function Xd(n) { _d0 = n; }     // setDebug
export function Xp(n) { _p = n; }      // setProxyIP
export function Xs(e,t) { _s5e = e; _s5a = t ?? ''; }  // setSocks5
export function Xg(e) { _s5g = e; }    // setSocks5Global
export function Xf(e) { _f0 = e; }     // setFallback
export function Xc(e) { _z = e; }      // setConfig
export function Xw2(e) { _s5w = e; }   // setSocks5Whitelist
export function Xp0(e) { _p0 = e; }    // setCacheProxyIP
export function Xp1(e) { _p1 = e; }    // setCacheResolved
export function Xp2(e) { _p2 = e; }    // setCacheIndex
export function Xs5(e) { _s5p = e; }   // setParsedSocks5Addr

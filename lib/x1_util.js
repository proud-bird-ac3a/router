// x1_util.js  — Uint8Array 工具 / socket 工具 / 随机函数 / log
// 映射:  b0=toBytes, b1=dataLen, b2=concatBytes, b3=TextEncoder, b4=TextDecoder
//        c0=closeSocket, c1=wsSend
//        E0=randomPath, E1=randomizeStars, E2=flattenArray
//        L0=log

import { _d0 } from './x0_cfg.js';

// ──── 编解码器 ────
const b3 = new TextEncoder();
const b4 = new TextDecoder();
export { b3, b4 };

// ──── Uint8Array 工具 ────
function b0(d) {                                 // 数据转Uint8Array
  if (d instanceof Uint8Array) return d;
  if (d instanceof ArrayBuffer) return new Uint8Array(d);
  if (ArrayBuffer.isView(d)) return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
  return new Uint8Array(d || 0);
}

function b1(d) {                                 // 有效数据长度
  if (!d) return 0;
  if (typeof d.byteLength === 'number') return d.byteLength;
  if (typeof d.length === 'number') return d.length;
  return 0;
}

function b2(...a) {                              // 拼接字节数据
  if (!a || a.length === 0) return new Uint8Array(0);
  const q = a.map(b0).filter(c => c.byteLength);
  const z = q.reduce((s, c) => s + c.byteLength, 0);
  const r = new Uint8Array(z);
  let o = 0;
  for (const c of q) { r.set(c, o); o += c.byteLength; }
  return r;
}

// ──── Socket 工具 ────
function c0(s) {                                 // closeSocketQuietly
  try { if (s?.readyState <= 2) s.close(); } catch (_) {}
}

async function c1(s, p) {                        // WebSocket发送并等待
  const r = s.send(p);
  if (r && typeof r.then === 'function') await r;
}

// ──── 随机 / 混淆 ────
const _W = [                                      // 常用路径目录 (匿名化)
  "about","account","acg","act","activity","ad","ads","ajax","album","albums","anime",
  "api","app","apps","archive","archives","article","articles","ask","auth","avatar",
  "bbs","bd","blog","blogs","book","books","bt","buy","cart","category","categories",
  "cb","channel","channels","chat","china","city","class","classify","clip","clips",
  "club","cn","code","collect","collection","comic","comics","community","company",
  "config","contact","content","course","courses","cp","data","detail","details",
  "dh","directory","discount","discuss","dl","dload","doc","docs","document","documents",
  "doujin","download","downloads","drama","edu","en","ep","episode","episodes",
  "event","events","f","faq","favorite","favourites","favs","feedback","file","files",
  "film","films","forum","forums","friend","friends","game","games","gif","go",
  "go.html","go.php","group","groups","help","home","hot","htm","html","image",
  "images","img","index","info","intro","item","items","ja","jp","jump","jump.html",
  "jump.php","jumping","knowledge","lang","lesson","lessons","lib","library",
  "link","links","list","live","lives","m","mag","magnet","mall","manhua","map",
  "member","members","message","messages","mobile","movie","movies","music","my",
  "new","news","note","novel","novels","online","order","out","out.html","out.php",
  "outbound","p","page","pages","pay","payment","pdf","photo","photos","pic","pics",
  "picture","pictures","play","player","playlist","post","posts","product","products",
  "program","programs","project","qa","question","rank","ranking","read","readme",
  "redirect","redirect.html","redirect.php","reg","register","res","resource",
  "retrieve","sale","search","season","seasons","section","seller","series",
  "service","services","setting","settings","share","shop","show","shows","site",
  "soft","sort","source","special","star","stars","static","stock","store","stream",
  "streaming","streams","student","study","tag","tags","task","teacher","team",
  "tech","temp","test","thread","tool","tools","topic","topics","torrent","trade",
  "travel","tv","txt","type","u","upload","uploads","url","urls","user","users",
  "v","version","videos","view","vip","vod","watch","web","wenku","wiki","work",
  "www","zh","zh-cn","zh-tw","zip"
];

const _R = 'abcdefghijklmnopqrstuvwxyz0123456789';  // 随机字符集

function E0(x = '/') {                           // 随机路径
  const n = Math.floor(Math.random() * 3 + 1);
  const s = _W.sort(() => 0.5 - Math.random()).slice(0, n).join('/');
  if (x === '/') return '/' + s;
  return '/' + s + x.replace('/?', '?');
}

function E1(t) {                                 // 替换星号为随机字符
  if (typeof t !== 'string' || !t.includes('*')) return t;
  return t.replace(/\*/g, () => {
    let s = '';
    for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++)
      s += _R[Math.floor(Math.random() * _R.length)];
    return s;
  });
}

async function E2(t) {                           // 整理成数组
  let s = String(t).replace(/[\t\"'\r\n]+/g, ',').replace(/,+/g, ',');
  if (s[0] === ',') s = s.slice(1);
  if (s[s.length - 1] === ',') s = s.slice(0, -1);
  return s.split(',');
}

// ──── 日志 ────
function L0(...a) {                              // log
  if (_d0) console.log(...a);
}

export { b0, b1, b2, c0, c1, E0, E1, E2, L0 };

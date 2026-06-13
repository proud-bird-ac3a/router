// g1_1101.js — Cloudflare 1101 error page
function g1e(h, ip) {
  const _h = h || 'unknown';
  const _i = ip || '0.0.0.0';
  return '<!DOCTYPE html>\n<html>\n<head>\n<title>Error 1101 - Worker threw exception</title>\n<style>\n* { margin: 0; padding: 0; box-sizing: border-box; }\nbody { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f7f7f8; color: #333; display: flex; justify-content: center; align-items: center; min-height: 100vh; }\n.card { background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 48px; text-align: center; max-width: 500px; }\nh1 { font-size: 48px; color: #e74c3c; margin-bottom: 8px; }\nh2 { font-size: 20px; font-weight: 400; color: #666; margin-bottom: 24px; }\n.code { background: #f1f1f1; border-radius: 4px; padding: 12px 16px; font-family: "SF Mono", Monaco, monospace; font-size: 13px; color: #888; word-break: break-all; text-align: left; margin: 8px 0; }\n.ray { font-size: 12px; color: #bbb; margin-top: 16px; }\n</style>\n</head>\n<body>\n<div class="card">\n<h1>1101</h1>\n<h2>Worker threw exception</h2>\n<div class="code">Host: ' + _h + '</div>\n<div class="code">Client IP: ' + _i + '</div>\n<div class="ray">Cloudflare Worker</div>\n</div>\n</body>\n</html>';
}
export { g1e };

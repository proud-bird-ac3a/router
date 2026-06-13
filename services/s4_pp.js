async function f0(url) {
  const q = url.searchParams;
  const pp = q.get('proxyip');
  if (pp) return { proxyIP: pp, fallback: true };
  return { proxyIP: '', fallback: q.get('nofallback') !== 'true' };
}
export { f0 };

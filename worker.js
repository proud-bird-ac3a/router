// worker.js — Cloudflare Worker entry point
import { R0 } from './router.js';

export default {
  async fetch(req, env, ctx) {
    try {
      return await R0(req, env, ctx);
    } catch (e) {
      return new Response(e?.message || 'Internal Error', { status: 500 });
    }
  }
};

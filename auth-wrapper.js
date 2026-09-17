import app from './_worker.js';

function isTruthy(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value ?? '').trim().toLowerCase());
}

function unauthorized() {
  return new Response('Unauthorized', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="CheckSocks5", charset="UTF-8"',
      'Cache-Control': 'no-store'
    }
  });
}

export default {
  async fetch(request, env, ctx) {
    // Escape hatch for the day upstream ships its own authentication.
    // Set AUTH_BYPASS=true in Cloudflare to disable this wrapper without changing code.
    if (isTruthy(env.AUTH_BYPASS)) {
      return app.fetch(request, env, ctx);
    }

    const user = String(env.AUTH_USER ?? '');
    const pass = String(env.AUTH_PASS ?? '');

    // Fail closed: never expose the app accidentally if credentials were not configured.
    if (!user || !pass) {
      return new Response('Authentication is not configured', {
        status: 503,
        headers: { 'Cache-Control': 'no-store' }
      });
    }

    const authorization = request.headers.get('Authorization') || '';
    const expected = `Basic ${btoa(`${user}:${pass}`)}`;

    if (authorization !== expected) {
      return unauthorized();
    }

    return app.fetch(request, env, ctx);
  }
};

const ALLOWED_ACTIONS = new Set(['chat_post', 'chat_delete', 'chat_blocked']);

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'content-type, x-admin-token',
      'access-control-allow-methods': 'GET, POST, OPTIONS'
    }
  });
}

function getMaskedIp(ip) {
  if (!ip) return 'unknown';
  if (ip.includes(':')) {
    const parts = ip.split(':').filter(Boolean);
    return `${parts.slice(0, 3).join(':')}::`;
  }
  const parts = ip.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.***`;
  return ip;
}

async function sha256Hex(text) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(String(text || ''));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const arr = Array.from(new Uint8Array(digest));
  return arr.map((v) => v.toString(16).padStart(2, '0')).join('');
}

function isAdmin(req, env) {
  const token = req.headers.get('x-admin-token') || '';
  return !!env.ADMIN_TOKEN && token === env.ADMIN_TOKEN;
}

function toSafeText(v, max = 220) {
  return String(v || '').slice(0, max);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return json({ ok: true });
    }

    if (url.pathname === '/api/audit/log' && request.method === 'POST') {
      let body = null;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: 'invalid_json' }, 400);
      }

      const action = String(body?.action || '').trim();
      if (!ALLOWED_ACTIONS.has(action)) {
        return json({ ok: false, error: 'invalid_action' }, 400);
      }

      const roomTag = toSafeText(body?.roomTag || 'modore-melos-board-v1', 64);
      const uid = toSafeText(body?.uid, 96);
      const pubkey = toSafeText(body?.pubkey, 128);
      const eventId = toSafeText(body?.eventId, 128);
      const targetEventId = toSafeText(body?.targetEventId, 128);
      const name = toSafeText(body?.name, 32);
      const text = toSafeText(body?.text, 300);

      const ip =
        request.headers.get('cf-connecting-ip') ||
        request.headers.get('x-forwarded-for') ||
        'unknown';
      const ipMasked = getMaskedIp(ip);
      const ipHash = await sha256Hex(`${ip}|${env.IP_SALT || 'fallback_salt'}`);
      const userAgent = toSafeText(request.headers.get('user-agent') || '-', 280);
      const createdAtMs = Date.now();

      const id = crypto.randomUUID();
      await env.DB.prepare(
        `INSERT INTO audit_logs (
          id, created_at_ms, action, room_tag, ip, ip_masked, ip_hash, user_agent,
          uid, pubkey, event_id, target_event_id, name, text, is_deleted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
      )
        .bind(
          id,
          createdAtMs,
          action,
          roomTag,
          ip,
          ipMasked,
          ipHash,
          userAgent,
          uid,
          pubkey,
          eventId,
          targetEventId,
          name,
          text
        )
        .run();

      return json({ ok: true, id });
    }

    if (url.pathname === '/api/audit/logs' && request.method === 'GET') {
      if (!isAdmin(request, env)) {
        return json({ ok: false, error: 'unauthorized' }, 401);
      }
      const limitRaw = Number(url.searchParams.get('limit') || 120);
      const limit = Math.max(1, Math.min(500, Number.isFinite(limitRaw) ? limitRaw : 120));
      const includeDeleted = url.searchParams.get('include_deleted') === '1';

      const query = includeDeleted
        ? `SELECT * FROM audit_logs ORDER BY created_at_ms DESC LIMIT ?`
        : `SELECT * FROM audit_logs WHERE is_deleted = 0 ORDER BY created_at_ms DESC LIMIT ?`;

      const result = await env.DB.prepare(query).bind(limit).all();
      const logs = Array.isArray(result?.results) ? result.results : [];
      return json({ ok: true, logs });
    }

    if (url.pathname === '/api/audit/mark-deleted' && request.method === 'POST') {
      if (!isAdmin(request, env)) {
        return json({ ok: false, error: 'unauthorized' }, 401);
      }
      let body = null;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: 'invalid_json' }, 400);
      }
      const eventIds = Array.isArray(body?.eventIds) ? body.eventIds : [];
      const unique = Array.from(
        new Set(eventIds.map((v) => String(v || '').trim()).filter(Boolean))
      ).slice(0, 400);
      if (unique.length === 0) {
        return json({ ok: true, updated: 0 });
      }
      let updated = 0;
      for (const id of unique) {
        const r = await env.DB.prepare(
          `UPDATE audit_logs
             SET is_deleted = 1
           WHERE event_id = ? OR target_event_id = ?`
        )
          .bind(id, id)
          .run();
        updated += r?.meta?.changes || 0;
      }
      return json({ ok: true, updated });
    }

    return json({ ok: false, error: 'not_found' }, 404);
  }
};

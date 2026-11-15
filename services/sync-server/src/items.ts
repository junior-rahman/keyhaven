// apps/sync-server/src/items.ts
import { Hono } from 'hono';
import type { DatabaseSync } from 'node:sqlite';
import * as z from 'zod/v4';
import { requireDevice } from './auth.js';

const Sealed = z.object({ v: z.literal(1), n: z.string().max(64), c: z.string().max(1_500_000) });
const ItemBlob = z.object({
  ver: z.number().int().min(1), // the item's own version, set by the device that edited it
  wrappedKey: Sealed,
  body: Sealed,
  deleted: z.boolean(),
});

function tx<T>(db: DatabaseSync, fn: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

export function itemRoutes(db: DatabaseSync) {
  const app = new Hono<{ Variables: { accountId: string } }>();
  app.use('*', requireDevice); // verifies the access token and sets accountId

  app.put('/v1/vaults/:vaultId/items/:itemId', async (c) => {
    const { vaultId, itemId } = c.req.param();
    const expected = Number(c.req.header('If-Match') ?? 0); // the seq this device last saw for the item
    const parsed = ItemBlob.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json({ error: 'bad_request' }, 400);
    const blob = parsed.data;

    const result = tx(db, () => {
      const vault = db.prepare('SELECT head FROM vault WHERE id = ? AND account_id = ?')
        .get(vaultId, c.get('accountId')) as { head: number } | undefined;
      if (!vault) return { status: 404 as const };

      const current = db.prepare('SELECT seq, ver, wrapped_key, body, deleted FROM item WHERE vault_id = ? AND id = ?')
        .get(vaultId, itemId) as { seq: number; ver: number } | undefined;
      if ((current?.seq ?? 0) !== expected) return { status: 409 as const, current };
      // A version may only go up. This is a courtesy check: devices do not rely on the server for it.
      if (current && blob.ver <= current.ver) return { status: 409 as const, current };

      const seq = vault.head + 1; // one counter per vault doubles as the changes cursor
      db.prepare('UPDATE vault SET head = ? WHERE id = ?').run(seq, vaultId);
      db.prepare(
        `INSERT INTO item (vault_id, id, seq, ver, wrapped_key, body, deleted) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (vault_id, id) DO UPDATE SET seq = excluded.seq, ver = excluded.ver,
         wrapped_key = excluded.wrapped_key, body = excluded.body, deleted = excluded.deleted`,
      ).run(vaultId, itemId, seq, blob.ver, JSON.stringify(blob.wrappedKey), JSON.stringify(blob.body), blob.deleted ? 1 : 0);
      return { status: 200 as const, seq };
    });

    if (result.status === 404) return c.json({ error: 'not_found' }, 404);
    if (result.status === 409) return c.json({ error: 'conflict', current: result.current }, 409);
    return c.json({ seq: result.seq });
  });

  return app;
}

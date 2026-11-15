import type { MiddlewareHandler } from 'hono';
export const requireDevice: MiddlewareHandler<{ Variables: { accountId: string } }> = async (c, next) => { c.set('accountId', 'acct_test'); await next(); };

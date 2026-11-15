// apps/mcp-server/src/tools/fill-login.ts
import type { CallToolResult, McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import type { CoreClient } from '../core-client.js';

export function registerFillLogin(server: McpServer, core: CoreClient) {
  server.registerTool(
    'fill_login',
    {
      title: 'Fill a login in the browser',
      description:
        'Fill the username and password of a Keyhaven item into the active browser tab. ' +
        "Works only when the tab's site matches the item's saved sites. The user approves in the Keyhaven app " +
        'with Windows Hello, which can take up to 45 seconds; the password is never returned to you.',
      inputSchema: z.object({
        itemId: z.uuid(),
        reason: z.string().max(200).describe('One sentence the user will see, labelled as coming from you'),
      }),
      outputSchema: z.object({
        status: z.enum(['filled', 'denied', 'expired', 'locked', 'not_found', 'no_matching_tab', 'rate_limited']),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    async ({ itemId, reason }): Promise<CallToolResult> => {
      // One call, one answer. The core checks the item's policy and the real tab, shows its own prompt,
      // runs Windows Hello itself and fills through the extension. Nothing this process sends can approve.
      const { status } = await core.call('fill.request', { itemId, reason });
      return { content: [{ type: 'text', text: `fill_login: ${status}` }], structuredContent: { status } };
    },
  );
}

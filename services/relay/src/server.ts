// apps/relay/src/server.ts
import { createServer } from 'node:http';
import {
  McpServer,
  createMcpHandler,
  createRequestStateCodec,
  inputRequired,
  inputResponse,
  type CallToolResult,
  type InputRequiredResult,
} from '@modelcontextprotocol/server';
import { toNodeHandler } from '@modelcontextprotocol/node';
import * as z from 'zod/v4';
import { device } from './device-link.stub.js'; // the outbound WebSocket your own Keyhaven app keeps open

type Wait = { approvalId: string };

// Signed, not encrypted: it carries only an approval id. Every relay instance shares the key.
const waiting = createRequestStateCodec<Wait>({
  key: new TextEncoder().encode(process.env.RELAY_STATE_KEY!),
  ttlSeconds: 180,
});

function buildServer(): McpServer {
  const server = new McpServer({ name: 'keyhaven-remote', version: '0.1.0' }, { requestState: { verify: waiting.verify } });

  server.registerTool(
    'get_totp',
    {
      title: 'Get a 2FA code',
      description: 'Ask for the current 2FA code of a Keyhaven item. The user approves on their own phone first.',
      inputSchema: z.object({ itemId: z.uuid(), reason: z.string().max(200) }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ itemId, reason }, ctx): Promise<CallToolResult | InputRequiredResult> => {
      const text = (t: string): CallToolResult => ({ content: [{ type: 'text', text: t }] });
      const state = ctx.mcpReq.requestState<Wait>();

      if (!state) {
        // Check before anything is sent to the phone: a client that cannot show the Continue step cannot finish.
        if (!server.server.getClientCapabilities()?.elicitation) return text('get_totp: this client cannot confirm approvals');
        // Round one: the device applies the item's policy and sends an approval request to the phone.
        const begin = await device.call('totp.begin', { itemId, reason });
        if (begin.status !== 'pending') return text(`get_totp: ${begin.status}`);
        return inputRequired({
          inputRequests: {
            approved: inputRequired.elicit({
              message: 'Approve this request in Keyhaven on your phone, then choose Continue.',
              requestedSchema: {
                type: 'object',
                properties: { continue: { type: 'boolean', title: 'Continue' } },
                required: ['continue'],
              },
            }),
          },
          requestState: await waiting.mint({ approvalId: begin.approvalId }),
        });
      }

      // Round two: what the client answered is only interface. The device's own approval record decides.
      const answer = inputResponse(ctx.mcpReq.inputResponses, 'approved');
      if (answer.kind === 'elicit' && answer.action !== 'accept') {
        await device.call('approval.cancel', { approvalId: state.approvalId });
        return text('get_totp: cancelled');
      }
      const result = await device.call('totp.collect', { approvalId: state.approvalId });
      return text(result.status === 'approved' ? `Code ${result.code}, valid for ${result.secondsLeft} s` : `get_totp: ${result.status}`);
    },
  );
  return server;
}

// A fresh server per request: no sessions to store, so any instance can answer any request.
const handler = createMcpHandler(buildServer, { responseMode: 'json' });
createServer(toNodeHandler(handler)).listen(Number(process.env.PORT ?? 8787), '127.0.0.1');

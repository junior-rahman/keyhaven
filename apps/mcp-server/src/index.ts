// apps/mcp-server/src/index.ts
import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { CoreClient } from './core-client.js';
import { registerFillLogin } from './tools/fill-login.js';
import { registerSearchItems } from './tools/search-items.js';

// Each AI client names its own profile in its MCP config, so it pairs, is scoped and is revoked on its own.
const core = await CoreClient.connect(process.env.KEYHAVEN_PROFILE ?? 'default');

const server = new McpServer({ name: 'keyhaven', version: '0.2.0' });
registerSearchItems(server, core); // always the same order, so clients can cache the list
registerFillLogin(server, core);

await server.connect(new StdioServerTransport());
console.error('keyhaven-mcp ready'); // stderr only: stdout carries protocol messages

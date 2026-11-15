// apps/mcp-server/src/core-client.ts
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';

const proof = (token: Buffer, label: string, clientNonce: Buffer, coreNonce: Buffer) =>
  createHmac('sha256', token).update(label).update(clientNonce).update(coreNonce).digest();

export class CoreClient {
  private nextId = 1;
  private waiting = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();

  private constructor(private socket: net.Socket) {
    createInterface({ input: socket }).on('line', (line) => {
      const msg = JSON.parse(line);
      const waiter = this.waiting.get(msg.id);
      if (!waiter) return;
      this.waiting.delete(msg.id);
      if (msg.error) waiter.reject(new Error(msg.error.message));
      else waiter.resolve(msg.result);
    });
    socket.on('close', () => {
      for (const w of this.waiting.values()) w.reject(new Error('Keyhaven is not running. Ask the user to open the Keyhaven app.'));
      this.waiting.clear();
    });
  }

  /** One profile per AI client (claude-desktop, claude-code), so each gets its own scopes and its own off switch. */
  static async connect(profile: string, pipe = `\\\\.\\pipe\\keyhaven-${os.userInfo().username}`): Promise<CoreClient> {
    const tokenFile = path.join(process.env.LOCALAPPDATA ?? os.homedir(), 'Keyhaven', 'clients', `${profile}.token`);
    const token = Buffer.from((await readFile(tokenFile, 'utf8')).trim(), 'base64url');
    const socket = net.connect(pipe);
    await new Promise<void>((resolve, reject) => socket.once('connect', resolve).once('error', reject));
    const core = new CoreClient(socket);

    // Mutual proof: the token never crosses the pipe, and a program squatting on the pipe name
    // cannot answer the first challenge, so we stop before sending it anything.
    const clientNonce = randomBytes(32);
    const started = await core.call('hello.start', { profile, clientNonce: clientNonce.toString('base64url') });
    const coreNonce = Buffer.from(started.coreNonce, 'base64url');
    const expected = proof(token, 'kh/v1/core', clientNonce, coreNonce);
    const got = Buffer.from(started.coreProof, 'base64url');
    if (got.length !== expected.length || !timingSafeEqual(got, expected)) {
      socket.destroy();
      throw new Error('The program answering on the Keyhaven pipe is not Keyhaven.');
    }
    await core.call('hello.finish', { clientProof: proof(token, 'kh/v1/client', clientNonce, coreNonce).toString('base64url') });
    return core;
  }

  call(method: string, params: unknown): Promise<any> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.waiting.set(id, { resolve, reject });
      this.socket.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }
}

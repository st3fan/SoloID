import { serve } from '@hono/node-server';
import { Server } from 'node:http';
import { createApp } from './app.js';
import { loadConfig } from './config.js';

const log = (event: Record<string, unknown>) => console.log(JSON.stringify(event));
async function main() {
  const path = process.env.SOLOID_CONFIG;
  if (!path) throw new Error('SOLOID_CONFIG is required');
  const port = Number(process.env.PORT ?? 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
  const provider = createApp(await loadConfig(path), log);
  const server = serve({ fetch: provider.app.fetch, port, hostname: '0.0.0.0' }, () => log({ event: 'listening', port }));
  if (server instanceof Server) {
    server.requestTimeout = 15000;
    server.headersTimeout = 10000;
  }
  let reloading = false;
  process.on('SIGHUP', async () => {
    if (reloading) return;
    reloading = true;
    try {
      provider.reload(await loadConfig(path));
      log({ event: 'config_reloaded' });
    } catch { log({ event: 'config_reload_failed', message: 'Keeping previous configuration. Run CLI check for details.' }); }
    finally { reloading = false; }
  });
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 10000).unref();
  });
}
main().catch(() => {
  console.error(JSON.stringify({ event: 'startup_failed', message: 'Check SOLOID_CONFIG, PORT, and configuration with CLI check.' }));
  process.exitCode = 1;
});

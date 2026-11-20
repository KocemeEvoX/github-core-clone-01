// Entry point: the lifecycle between this forge and the make.fun trial env.
//
// The env drives the whole trial. This process does four things, in order:
//   1. Read MAKEFUN_ENV_URL. Without it there is no env to talk to, so exit 1.
//   2. Bind the forge to an ephemeral port (listen(0); never 8080, the env owns it)
//      and tell the env that port with POST /register {"port": N}. The first
//      register wins: a 200 means we registered, a 409 means another entry
//      registered first and we simply wait like any other process.
//   3. Poll GET /done until the env answers {"done": true}. The env answers
//      immediately ({"done": false} while the trial runs), so this is a poll,
//      not a long-held request. The process never exits before the env says done.
//   4. Close the server and exit 0. The env then writes the export the scorer reads.
//
// The forge itself lives in app.ts; this file only owns the handshake above.

import { createApp } from './app.ts';

// The env's origin, e.g. http://store:8080 inside a trial container.
const envUrl = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (envUrl === '') {
  process.stderr.write('[entry] MAKEFUN_ENV_URL is not set: there is no env to register with\n');
  process.exit(1);
}

// One register or /done request may take this long before it is abandoned.
const REQUEST_TIMEOUT_MS = 30_000;
// Backoff between retries: starts here, doubles, and never passes the cap.
const BACKOFF_FIRST_MS = 250;
const BACKOFF_MAX_MS = 2_000;

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

function backoffMs(failedAttempts: number): number {
  return Math.min(BACKOFF_MAX_MS, BACKOFF_FIRST_MS * 2 ** Math.min(failedAttempts, 8));
}

/**
 * Tell the env which port the forge bound. 200 and 409 both mean "registered"
 * (409: a first register already won). 400 and 405 are contract errors and end
 * the program. Anything else — a network error, a timeout, another status —
 * is retried, because the env may still be starting up.
 */
async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${envUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) {
        throw new Error(`register answered HTTP ${res.status}: ${await res.text()}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(backoffMs(attempt));
  }
}

/** Keep polling GET /done until the env says the trial is over. */
async function waitUntilDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${envUrl}/done`, {
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // The env is not answering yet, or the poll timed out: not done, poll again.
    }
    await sleep(backoffMs(attempt));
  }
}

async function main(): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('the server did not bind an ephemeral TCP port');
  }
  process.stdout.write(`[entry] listening on port ${address.port}\n`);

  await register(address.port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');

  await waitUntilDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await main();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}

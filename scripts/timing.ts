import { performance } from 'node:perf_hooks';
import { createApp } from '../src/app.js';
import { fixture, Browser, authParams } from '../test/helpers.js';

// Disposable fixtures only. Never probe real accounts or weaken production limits.
const runtime = await fixture();
const samples: Record<string, number[]> = { known: [], unknown: [] };
for (let i = 0; i < 110; i++) {
  const order = i % 2 ? ['unknown', 'known'] : ['known', 'unknown'];
  for (const kind of order) {
    const { app } = createApp(runtime, () => {});
    const browser = new Browser(app);
    await browser.start(authParams());
    const start = performance.now();
    const result = await browser.login(kind === 'known' ? 'one@example.com' : 'absent@example.com', 'same invalid password');
    await result.text();
    if (result.status !== 401) throw new Error(`Unexpected status: ${result.status}`);
    if (i >= 10) samples[kind].push(performance.now() - start);
  }
}
for (const [kind, times] of Object.entries(samples)) {
  times.sort((a, b) => a - b);
  console.log(`${kind}: n=${times.length} median=${times[50].toFixed(2)}ms p95=${times[95].toFixed(2)}ms`);
}
console.log('Compare distributions, not exact elapsed times. This is a diagnostic, not a proof of timing indistinguishability.');

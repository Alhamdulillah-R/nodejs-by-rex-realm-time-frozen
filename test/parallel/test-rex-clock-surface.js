'use strict';
// Verifies the opt-in Chromium-shaped clock surface:
//   REX_CLOCK_RESOLUTION_NS  performance.now() quantum (Blink TimeClamper)
//   REX_TIMER_NESTING_CLAMP  Blink DOMTimer nesting semantics
//   REX_TIMER_GRID_MS        coarse scheduler tick emulation
require('../common');
const assert = require('assert');
const { spawnSync } = require('child_process');

function runChild(env, script) {
  const result = spawnSync(process.execPath, ['-e', script], {
    env: { ...process.env, ...env },
    encoding: 'utf8',
  });
  assert.strictEqual(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

const off = {
  REX_CLOCK_RESOLUTION_NS: '',
  REX_TIMER_NESTING_CLAMP: '',
  REX_TIMER_GRID_MS: '',
};

// 1. Stock behaviour is untouched when nothing is set.
{
  const r = runChild(off, `
    const v = Array.from({ length: 5000 }, () => performance.now());
    const t = setTimeout(() => {}, 0);
    console.log(JSON.stringify({ distinct: new Set(v).size,
                                 idle: t._idleTimeout }));
    clearTimeout(t);
  `);
  assert.ok(r.distinct > 2500, `distinct=${r.distinct}`);
  assert.strictEqual(r.idle, 1);
}

// 2. 100us quantum: every value sits on the 0.1ms grid, repeats inside a
//    bucket, never goes backwards, and Event.timeStamp follows.
{
  const r = runChild({ ...off, REX_CLOCK_RESOLUTION_NS: '100000' }, `
    const v = Array.from({ length: 20000 }, () => performance.now());
    const onGrid = (x) => Math.abs(x * 10 - Math.round(x * 10)) < 1e-6;
    let backwards = 0;
    for (let i = 1; i < v.length; i++) if (v[i] < v[i - 1]) backwards++;
    const e = new Event('x');
    // Blink shape: values sit on the 0.1ms grid only up to the float noise of
    // clamp(now) - clamp(origin), and timeOrigin is on the grid too.
    console.log(JSON.stringify({
      distinct: new Set(v).size,
      offGrid: v.filter((x) => !onGrid(x)).length,
      backwards,
      eventOnGrid: onGrid(e.timeStamp),
      originOnGrid: (String(performance.timeOrigin).split('.')[1] || '').length <= 1,
    }));
  `);
  assert.strictEqual(r.offGrid, 0);
  assert.strictEqual(r.backwards, 0);
  assert.ok(r.distinct < 10000, `distinct=${r.distinct}`);
  assert.strictEqual(r.eventOnGrid, true);
  assert.strictEqual(r.originOnGrid, true);
}

// 3. Nesting clamp: a top-level 0 stays 0, the seventh timer of a chain is
//    the first raised to 4ms (Chrome 152: kSpecCompliantMaxTimerNestingLevel
//    = 6, clamp when nesting_level > 6).
{
  const r = runChild({ ...off, REX_TIMER_NESTING_CLAMP: '1' }, `
    const levels = [];
    const top = setTimeout(() => {}, 0);
    const topIdle = top._idleTimeout;
    clearTimeout(top);
    (function chain() {
      const t = setTimeout(() => {
        if (levels.length < 9) chain();
        else console.log(JSON.stringify({ topIdle, levels }));
      }, 0);
      levels.push(t._idleTimeout);
    })();
  `);
  assert.strictEqual(r.topIdle, 0);
  assert.deepStrictEqual(r.levels, [0, 0, 0, 0, 0, 0, 4, 4, 4]);
}

// 4. Grid: a 1ms timer chain follows the 15.625ms tick train.
{
  const r = runChild({ ...off, REX_TIMER_GRID_MS: '15.625' }, `
    const d = [];
    let last = performance.now();
    let n = 0;
    (function tick() {
      const now = performance.now();
      if (n > 0) d.push(now - last);
      last = now;
      if (++n > 40) {
        d.sort((a, b) => a - b);
        console.log(JSON.stringify({ p50: d[20] }));
        return;
      }
      setTimeout(tick, 1);
    })();
  `);
  assert.ok(r.p50 > 12 && r.p50 < 20, `p50=${r.p50}`);
}

// 5. Invalid values fail loudly instead of being ignored.
{
  const result = spawnSync(process.execPath, ['-e', '0'], {
    env: { ...process.env, ...off, REX_TIMER_NESTING_CLAMP: 'yes' },
    encoding: 'utf8',
  });
  assert.notStrictEqual(result.status, 0);
  assert.match(result.stderr, /REX_TIMER_NESTING_CLAMP/);
}

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

// 5. RexMirror.clock: non-enumerable global; presets switch the surface at
//    runtime; bad values throw.
{
  const r = runChild(off, `
    const desc = Object.getOwnPropertyDescriptor(globalThis, 'RexMirror');
    const before = RexMirror.clock.get();
    const chrome = RexMirror.clock.use('chrome');
    const host = RexMirror.clock.hostPlatform;
    const expectedChrome = RexMirror.clock.presets.chrome[host];
    const chromeWindows = RexMirror.clock.use('chrome', 'windows');
    const nodeWindows = RexMirror.clock.use('node', 'windows');
    const winchromeWindows = RexMirror.clock.use('winchrome', 'windows');
    const winchromeLinux = RexMirror.clock.use('winchrome', 'linux');
    const info = RexMirror.info;
    let badPlatform = null;
    try { RexMirror.clock.use('chrome', 'mac'); } catch (e) { badPlatform = e.code; }
    RexMirror.clock.use('chrome');
    const t = setTimeout(() => {}, 0);
    const idle = t._idleTimeout;
    clearTimeout(t);
    const v = Array.from({ length: 5000 }, () => performance.now());
    const onGrid = (x) => Math.abs(x * 10 - Math.round(x * 10)) < 1e-6;
    let bad = null;
    try { RexMirror.clock.set({ resolutionNs: -1 }); } catch (e) { bad = e.name; }
    let badName = null;
    try { RexMirror.clock.use('nope'); } catch (e) { badName = e.code; }
    // platformTimerResolutionMs is informational and machine-specific.
    const pick = ({ resolutionNs, nestingClamp, timerGridMs, highResolutionTimer }) =>
      ({ resolutionNs, nestingClamp, timerGridMs, highResolutionTimer });
    console.log(JSON.stringify({
      enumerable: desc.enumerable,
      writable: desc.writable,
      inKeys: Object.keys(globalThis).includes('RexMirror'),
      before: pick(before), chrome: pick(chrome), idle,
      expectedChrome: pick(expectedChrome),
      chromeWindows: pick(chromeWindows), nodeWindows: pick(nodeWindows),
      winchromeWindows: pick(winchromeWindows),
      winchromeLinux: pick(winchromeLinux),
      info: {
        serial: info.serial, lyric: info.lyric, song: info.song, date: info.date,
        node: info.node, banner: info.banner, releases: info.releases.length,
        frozen: Object.isFrozen(info) && Object.isFrozen(info.releases) &&
          info.releases.every((r) => Object.isFrozen(r) && Object.isFrozen(r.changes)),
        last: info.releases[info.releases.length - 1].lyric,
      },
      version: process.version,
      badPlatform,
      platformResolutionIsNumber: typeof chrome.platformTimerResolutionMs === 'number',
      offGrid: v.filter((x) => !onGrid(x)).length,
      distinct: new Set(v).size,
      bad, badName,
      after: pick(RexMirror.clock.set({ timerGridMs: 15.625 })),
    }));
  `);
  assert.strictEqual(r.enumerable, false);
  assert.strictEqual(r.writable, false);
  assert.strictEqual(r.inKeys, false);
  assert.deepStrictEqual(r.before, {
    resolutionNs: 0, nestingClamp: false, timerGridMs: 0,
    highResolutionTimer: false,
  });
  assert.deepStrictEqual(r.chrome, r.expectedChrome);
  assert.deepStrictEqual(r.chromeWindows, {
    resolutionNs: 100000, nestingClamp: true, timerGridMs: 1,
    highResolutionTimer: true,
  });
  assert.deepStrictEqual(r.nodeWindows, {
    resolutionNs: 100, nestingClamp: false, timerGridMs: 15.625,
    highResolutionTimer: false,
  });
  // winchrome: same grid on both hosts; only the Windows variant takes over
  // the system timer so the OS tick cannot round on top of the grid.
  assert.deepStrictEqual(r.winchromeWindows, {
    resolutionNs: 100000, nestingClamp: true, timerGridMs: 15.625,
    highResolutionTimer: true,
  });
  assert.deepStrictEqual(r.winchromeLinux, {
    resolutionNs: 100000, nestingClamp: true, timerGridMs: 15.625,
    highResolutionTimer: false,
  });
  // Release record: named by a lyric, `node --version` stays upstream's.
  assert.strictEqual(r.version, 'v26.7.0');
  assert.strictEqual(r.info.serial, 1);
  assert.strictEqual(r.info.lyric, 'she Medusa with a little Pocahontas');
  assert.strictEqual(r.info.song, 'Wasted');
  assert.strictEqual(r.info.date, '2026-09-04');
  assert.strictEqual(r.info.node, '26.7.0');
  assert.strictEqual(r.info.last, r.info.lyric);
  assert.ok(r.info.releases >= 1);
  assert.strictEqual(r.info.frozen, true);
  assert.strictEqual(
    r.info.banner,
    'RexMirror #1 "she Medusa with a little Pocahontas" (Wasted) on Node 26.7.0, 2026-09-04');
  assert.strictEqual(r.badPlatform, 'ERR_INVALID_ARG_VALUE');
  assert.strictEqual(r.platformResolutionIsNumber, true);
  assert.strictEqual(r.idle, 0);
  assert.strictEqual(r.offGrid, 0);
  assert.ok(r.distinct < 2500, `distinct=${r.distinct}`);
  assert.strictEqual(r.bad, 'RangeError');
  assert.strictEqual(r.badName, 'ERR_INVALID_ARG_VALUE');
  assert.deepStrictEqual(r.after, {
    ...r.expectedChrome, timerGridMs: 15.625,
  });
}

// 6. Time zone: IANA names apply to the whole isolate (vm contexts too),
//    bad names throw, get() reports the zone.
{
  const r = runChild(off, `
    const vm = require('vm');
    const ctx = vm.createContext({});
    const taipei = RexMirror.clock.setTimeZone('Asia/Taipei');
    const offTaipei = new Date(Date.UTC(2026, 0, 15)).getTimezoneOffset();
    const ctxTaipei = vm.runInContext('new Date(Date.UTC(2026, 0, 15)).getTimezoneOffset()', ctx);
    const ny = RexMirror.clock.set({ timeZone: 'America/New_York' });
    const offNy = new Date(Date.UTC(2026, 0, 15)).getTimezoneOffset();
    const intlNy = new Intl.DateTimeFormat('en-US').resolvedOptions().timeZone;
    let bad = null;
    try { RexMirror.clock.setTimeZone('Mars/Olympus'); } catch (e) { bad = e.code; }
    let badType = null;
    try { RexMirror.clock.set({ timeZone: 5 }); } catch (e) { badType = e.code; }
    console.log(JSON.stringify({
      taipeiTz: taipei.timeZone, taipeiOff: taipei.timezoneOffsetMinutes,
      offTaipei, ctxTaipei,
      nyTz: ny.timeZone, offNy, intlNy, bad, badType,
      stillNy: RexMirror.clock.get().timeZone,
    }));
  `);
  assert.strictEqual(r.taipeiTz, 'Asia/Taipei');
  assert.strictEqual(r.offTaipei, -480);
  assert.strictEqual(r.ctxTaipei, -480);
  assert.strictEqual(r.nyTz, 'America/New_York');
  assert.strictEqual(r.offNy, 300);
  assert.strictEqual(r.intlNy, 'America/New_York');
  assert.strictEqual(r.bad, 'ERR_INVALID_ARG_VALUE');
  assert.strictEqual(r.badType, 'ERR_INVALID_ARG_TYPE');
  assert.strictEqual(r.stillNy, 'America/New_York');
}

// 7. Clock trace records every observable read; rules shift the clocks
//    without touching the shape.
{
  const r = runChild({ ...off, REX_CLOCK_RESOLUTION_NS: '100000',
                       REX_TIMER_NESTING_CLAMP: '1' }, `
    const dateBefore = Date.now();
    const rules = RexMirror.clock.rules.set({ performanceNowOffsetMs: 1500,
                                              dateOffsetMs: -86400000 });
    const dateShift = dateBefore - Date.now();
    const perfAfterRule = performance.now();
    const onGrid = (x) => Math.abs(x * 10 - Math.round(x * 10)) < 1e-6;
    const started = RexMirror.clock.trace.start({ capacity: 1000 });
    performance.now();
    Date.now();
    setTimeout(() => {
      const out = RexMirror.clock.trace.drain();
      const stopped = RexMirror.clock.trace.stop();
      const kinds = {};
      for (const rec of out.records) kinds[rec.kind] = (kinds[rec.kind] || 0) + 1;
      const create = out.records.find((x) => x.kind === 'timer.create');
      const fire = out.records.find((x) => x.kind === 'timer.fire');
      const perf = out.records.find((x) => x.kind === 'performance.now');
      const date = out.records.find((x) => x.kind === 'date');
      const vm = require('vm');
      RexMirror.clock.trace.start({ capacity: 100 });
      vm.runInNewContext('performance.now(); Date.now();', { performance });
      const vmOut = RexMirror.clock.trace.drain();
      const vmContexts = vmOut.records.map((x) => x.kind + ':' + x.context);
      // runAsTask dispatches like a fresh browser task: nesting level 0 inside.
      const taskLevels = {
        inner: RexMirror.clock.timers.nestingLevel(),
        insideTask: RexMirror.clock.timers.runAsTask(() => RexMirror.clock.timers.nestingLevel()),
        after: RexMirror.clock.timers.nestingLevel(),
      };
      let badTask = null;
      try { RexMirror.clock.timers.runAsTask(5); } catch (e) { badTask = e.code; }
      let bad = null;
      try { RexMirror.clock.rules.set({ dateOffsetMs: Infinity }); } catch (e) { bad = e.name; }
      let badCap = null;
      try { RexMirror.clock.trace.start({ capacity: 0 }); } catch (e) { badCap = e.name; }
      console.log(JSON.stringify({
        perfContext: perf.context, dateContext: date.context, vmContexts,
        taskLevels, badTask,
        rules, dateShift, perfAfterRule, perfOnGrid: onGrid(perfAfterRule),
        startedEnabled: started.enabled, stoppedEnabled: stopped.enabled,
        kinds, create, fire, perfValueOnGrid: onGrid(perf.value),
        ordered: out.records.every((x, i) => i === 0 || x.seq > out.records[i - 1].seq),
        dropped: out.dropped, total: out.total, bad, badCap,
        rawKeys: Object.keys(RexMirror.clock.trace.drain({ raw: true })),
      }));
    }, 5);
  `);
  assert.strictEqual(r.perfContext, 'main');
  assert.strictEqual(r.dateContext, 'main');
  // performance.now attributes to the realm whose function ran: the main
  // realm's performance object was handed into the vm, so its read is 'main';
  // Date is the vm's own intrinsic, so that read is 'vm'.
  assert.deepStrictEqual(r.vmContexts, ['performance.now:main', 'date:vm']);
  assert.deepStrictEqual(r.taskLevels, { inner: 1, insideTask: 0, after: 1 });
  assert.strictEqual(r.badTask, 'ERR_INVALID_ARG_TYPE');
  assert.deepStrictEqual(r.rules, { performanceNowOffsetMs: 1500, dateOffsetMs: -86400000 });
  assert.ok(r.dateShift >= 86399000 && r.dateShift <= 86401000, `dateShift=${r.dateShift}`);
  assert.ok(r.perfAfterRule >= 1500, `perf=${r.perfAfterRule}`);
  assert.strictEqual(r.perfOnGrid, true);
  assert.strictEqual(r.startedEnabled, true);
  assert.strictEqual(r.stoppedEnabled, false);
  assert.ok(r.kinds['performance.now'] >= 1);
  assert.ok(r.kinds.date >= 1);
  assert.strictEqual(r.kinds['timer.create'], 1);
  assert.strictEqual(r.kinds['timer.fire'], 1);
  assert.strictEqual(r.create.requestedMs, 5);
  assert.strictEqual(r.create.appliedMs, 5);
  assert.strictEqual(r.create.nesting, 1);
  assert.strictEqual(r.fire.scheduledMs, 5);
  assert.ok(r.fire.elapsedMs >= 4, `elapsed=${r.fire.elapsedMs}`);
  assert.strictEqual(r.perfValueOnGrid, true);
  assert.strictEqual(r.ordered, true);
  assert.strictEqual(r.dropped, 0);
  assert.ok(r.total >= 4);
  assert.strictEqual(r.bad, 'RangeError');
  assert.strictEqual(r.badCap, 'RangeError');
  assert.deepStrictEqual(r.rawKeys,
                         ['count', 'seq', 'kind', 'realMs', 'value', 'aux0', 'aux1', 'dropped', 'total']);
}

// 8. Invalid environment values fail loudly instead of being ignored.
{
  const result = spawnSync(process.execPath, ['-e', '0'], {
    env: { ...process.env, ...off, REX_TIMER_NESTING_CLAMP: 'yes' },
    encoding: 'utf8',
  });
  assert.notStrictEqual(result.status, 0);
  assert.match(result.stderr, /REX_TIMER_NESTING_CLAMP/);
}

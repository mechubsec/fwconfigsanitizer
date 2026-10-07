'use strict';
// H3a fixture-suite harness. Extracts the fwconfigsanitizer engine from
// index.html (unmodified) and runs the 100-case regression suite from the
// MEC-6 privacy review's "Proposed fwconfigsanitizer fixture suite".
//
// Usage:
//   node test/run.js                  # human-readable table + summary, exit 1 on unexpected drift
//   node test/run.js --json out.json  # also write a machine-readable report
//   node test/run.js --md out.md      # also write the PASS/FAIL table as markdown
//
// "Drift" means a case's actual status no longer matches the `expected`
// status recorded from the review's table at commit 99c5186. Known failures
// are expected (that's the point of the suite before a fix lands); the
// harness only fails CI when a case's actual result no longer matches what's
// on record, i.e. a regression (or an undocumented improvement) happened.

const fs = require('node:fs');
const path = require('node:path');

const { loadEngine, INDEX_HTML_PATH } = require('./extract-engine');
const { cases } = require('./cases');
const { makeCrossCuttingCases, DEFAULT_SALT } = require('./cross-cutting');

// The page's CSP pins script-src to a hash of the single inline <script>
// block (see index.html's <head> comment). If that block's text changes
// without the hash being recomputed, the browser will silently refuse to run
// the app at all under its own CSP - fail loudly here instead.
function checkCspScriptHash() {
  const html = fs.readFileSync(INDEX_HTML_PATH, 'utf8');
  const tag = '<' + 'script>';
  const start = html.lastIndexOf(tag) + tag.length;
  const end = html.lastIndexOf('</' + 'script>');
  if (start <= tag.length - 1 || end === -1 || end <= start) {
    throw new Error('Could not locate the inline <script> block to verify its CSP hash.');
  }
  const scriptContent = html.slice(start, end);
  const actualHash = 'sha256-' + require('node:crypto').createHash('sha256').update(scriptContent, 'utf8').digest('base64');

  const cspMatch = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);
  if (!cspMatch) {
    throw new Error('No Content-Security-Policy meta tag found in index.html.');
  }
  const hashMatch = cspMatch[1].match(/script-src '(sha256-[^']+)'/);
  if (!hashMatch) {
    throw new Error('CSP meta tag has no script-src sha256 hash.');
  }
  if (hashMatch[1] !== actualHash) {
    throw new Error(
      `CSP script-src hash is stale: meta tag has ${hashMatch[1]}, actual inline script hashes to ${actualHash}. ` +
      'Recompute per the instructions in index.html\'s <head> comment.'
    );
  }
}

async function runStandardCase(engine, testCase) {
  const result = await engine.sanitizeConfig(testCase.input, {}, DEFAULT_SALT, []);
  const leaked = testCase.leakTokens.filter((tok) => result.sanitizedText.includes(tok));
  // mustSurvive (optional): text that must remain verbatim in the output, so
  // a "fix" that deletes the whole line instead of surgically redacting it
  // doesn't count as passing (see case 18: the `syslog host` keyword must
  // survive even after the hostname argument is redacted).
  const missingSurvivors = (testCase.mustSurvive || []).filter((tok) => !result.sanitizedText.includes(tok));
  const actualStatus = leaked.length > 0 || missingSurvivors.length > 0 ? 'FAIL' : 'PASS';
  const detailParts = [];
  if (leaked.length > 0) detailParts.push(`leaked: ${leaked.map((t) => JSON.stringify(t)).join(', ')}`);
  if (missingSurvivors.length > 0) detailParts.push(`missing required text: ${missingSurvivors.map((t) => JSON.stringify(t)).join(', ')}`);
  return {
    id: testCase.id,
    group: testCase.group,
    description: testCase.description,
    expected: testCase.expected,
    actualStatus,
    detail: detailParts.length > 0 ? detailParts.join('; ') : 'all tokens redacted',
    sanitizedText: result.sanitizedText,
    replacements: result.replacements,
  };
}

// Case 100: residual-original check. For every fixture we ran sanitizeConfig
// on (cases 1-94 plus the sanitizeConfig-based cross-cutting cases 96-98),
// no replacements[i].original longer than 3 characters may still appear in
// that same fixture's sanitizedText.
function runResidualOriginalCheck(fixtureRuns) {
  const violations = [];
  for (const run of fixtureRuns) {
    for (const r of run.replacements) {
      if (typeof r.original === 'string' && r.original.length > 3) {
        if (run.sanitizedText.includes(r.original)) {
          violations.push({ caseId: run.id, type: r.type, original: r.original });
        }
      }
    }
  }
  const ok = violations.length === 0;
  return {
    id: 100, group: 'cross-cutting', expected: 'PASS',
    description: 'Residual-original check: no replacements[i].original longer than 3 characters appears in the output',
    actualStatus: ok ? 'PASS' : 'FAIL',
    detail: ok
      ? 'no residual originals found'
      : `${violations.length} residual original(s), e.g. case ${violations[0].caseId} (${violations[0].type}): ${JSON.stringify(violations[0].original)}`,
  };
}

async function main() {
  const args = process.argv.slice(2);
  const jsonOutIdx = args.indexOf('--json');
  const mdOutIdx = args.indexOf('--md');
  const jsonOut = jsonOutIdx !== -1 ? args[jsonOutIdx + 1] : null;
  const mdOut = mdOutIdx !== -1 ? args[mdOutIdx + 1] : null;

  checkCspScriptHash();

  const { engine, startLineNo, endLineNo } = loadEngine();

  const standardResults = [];
  for (const c of cases) {
    standardResults.push(await runStandardCase(engine, c));
  }

  const crossCutting = await makeCrossCuttingCases(engine);

  // Case 100 needs sanitizedText+replacements from every sanitizeConfig call
  // in the corpus. Cases 1-94 already have that; cases 96/97 also call
  // sanitizeConfig internally, so we recompute those two lightly here rather
  // than threading state out of cross-cutting.js.
  const sanitizeConfigFixtureRuns = [...standardResults];
  const extra96 = await engine.sanitizeConfig(
    Array.from({ length: 254 }, (_, i) => `set FAKE-HOST-${i + 1} address 192.0.2.${i + 1}`).join('\n') + '\n',
    {}, DEFAULT_SALT, []
  );
  const extra97 = await engine.sanitizeConfig(
    'set fqdn "fakeorg97a.example.org"\nset url "https://fakeorg97b.example.com/path"\n',
    {}, DEFAULT_SALT, []
  );
  sanitizeConfigFixtureRuns.push(
    { id: 96, sanitizedText: extra96.sanitizedText, replacements: extra96.replacements },
    { id: 97, sanitizedText: extra97.sanitizedText, replacements: extra97.replacements }
  );

  const case100 = runResidualOriginalCheck(sanitizeConfigFixtureRuns);

  const allResults = [...standardResults, ...crossCutting, case100].sort((a, b) => a.id - b.id);

  const drift = allResults.filter((r) => r.actualStatus !== r.expected);

  // --- console summary ---
  const passCount = allResults.filter((r) => r.actualStatus === 'PASS').length;
  const failCount = allResults.filter((r) => r.actualStatus === 'FAIL').length;

  console.log(`fwconfigsanitizer fixture suite — engine extracted from index.html:${startLineNo}-${endLineNo}`);
  console.log(`${allResults.length} cases: ${passCount} PASS, ${failCount} FAIL (per the review's convention: FAIL = leak reproduced)\n`);

  for (const r of allResults) {
    const mark = r.actualStatus === r.expected ? '  ' : '**';
    console.log(`${mark}#${String(r.id).padStart(3)} [${r.group}] ${r.actualStatus} (expected ${r.expected}) — ${r.description}`);
  }

  if (drift.length > 0) {
    console.log(`\n${drift.length} case(s) drifted from the recorded MEC-6 table:`);
    for (const r of drift) {
      console.log(`  #${r.id}: expected ${r.expected}, got ${r.actualStatus} — ${r.detail}`);
    }
  } else {
    console.log('\nNo drift: every case matches the MEC-6 review table exactly.');
  }

  if (jsonOut) {
    const report = {
      generatedAt: new Date().toISOString(),
      engineRange: { start: startLineNo, end: endLineNo },
      summary: { total: allResults.length, pass: passCount, fail: failCount, drift: drift.length },
      cases: allResults.map((r) => ({
        id: r.id, group: r.group, description: r.description,
        expected: r.expected, actual: r.actualStatus, detail: r.detail,
      })),
    };
    fs.mkdirSync(path.dirname(jsonOut), { recursive: true });
    fs.writeFileSync(jsonOut, JSON.stringify(report, null, 2));
    console.log(`\nJSON report written to ${jsonOut}`);
  }

  if (mdOut) {
    const lines = [
      '# fwconfigsanitizer fixture suite report',
      '',
      `Engine extracted from \`index.html:${startLineNo}-${endLineNo}\`.`,
      '',
      '| # | Group | Status | Expected | Description |',
      '|---|---|---|---|---|',
      ...allResults.map(
        (r) => `| ${r.id} | ${r.group} | ${r.actualStatus} | ${r.expected} | ${r.description.replace(/\|/g, '\\|')} |`
      ),
      '',
      `${allResults.length} cases: ${passCount} PASS, ${failCount} FAIL.`,
      drift.length > 0 ? `${drift.length} case(s) drifted from the recorded MEC-6 table.` : 'No drift from the recorded MEC-6 table.',
    ];
    fs.mkdirSync(path.dirname(mdOut), { recursive: true });
    fs.writeFileSync(mdOut, lines.join('\n') + '\n');
    console.log(`Markdown report written to ${mdOut}`);
  }

  process.exitCode = drift.length > 0 ? 1 : 0;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

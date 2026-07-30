#!/usr/bin/env node
/**
 * Adapter B — repair the GitHub Release bodies that Lerna leaves empty on a graduation.
 *
 * `lerna publish --conventional-graduate` resolves conventional-changelog's `from` to the last
 * PRERELEASE tag of the package, so the commit range is empty and the release body becomes the
 * sentinel `**Note:** Version bump only for package <pkg>`. The detail is not lost — every
 * prerelease published its own itemised release — so this patches the release BODY only:
 * no commit, no push, no bypass actor, no workflow re-trigger.
 *
 * Runs post-publish on the default branch. Read-only against git; the only writes are
 * PATCH /repos/{repo}/releases/{id} on releases this run just created.
 *
 * Env:
 *   GITHUB_TOKEN / GH_TOKEN     App token minted by the release job (contents:write)
 *   GITHUB_REPOSITORY           owner/name
 *   GITHUB_API_URL              set by Actions
 *   GRADUATION_NOTES_SPEC       npm spec to install, default '@side/graduation-notes@^1'
 *   GRADUATION_NOTES_BIN        pre-resolved engine bin.mjs; skips the install (tests, vendoring)
 *   GRADUATION_NOTES_DRY_RUN    '1' → compute and print, never PATCH
 *   RUNNER_TEMP                 install prefix, default os.tmpdir()
 *
 * Exit codes:
 *   0  patched, or a deliberate no-op (incl. engine unavailable — never break a release for it)
 *   1  the mechanism failed on a release it should have repaired (loud)
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const SENTINEL_RE = /Version bump only for package/;
const COMPARE_RE = /\/compare\/(.+?)\.\.\./;
const DEFAULT_SPEC = '@side/graduation-notes@^1';

const log = (m) => process.stderr.write(`${m}\n`);
const warn = (m) => process.stderr.write(`::warning::${m}\n`);
const error = (m) => process.stderr.write(`::error::${m}\n`);

/* --------------------------------------------------------------- engine -- */

/**
 * The engine is a published package, not a script path (design §2) — the same artifact
 * Adapter A resolves through `@side/semantic-config-base`, so the two paths can never drift.
 * It is installed at release time rather than vendored, which also means it degrades to a
 * documented no-op for as long as it is unpublished.
 */
function resolveEngine() {
  const override = process.env.GRADUATION_NOTES_BIN;
  if (override) {
    if (existsSync(override)) return override;
    warn(
      `graduation-notes: GRADUATION_NOTES_BIN=${override} does not exist — skipping`,
    );
    return null;
  }

  const spec = process.env.GRADUATION_NOTES_SPEC || DEFAULT_SPEC;
  const name = spec.startsWith('@')
    ? `@${spec.slice(1).split('@')[0]}`
    : spec.split('@')[0];
  const prefix = join(process.env.RUNNER_TEMP || tmpdir(), 'graduation-notes');

  const res = spawnSync(
    'npm',
    [
      'install',
      '--prefix',
      prefix,
      '--no-audit',
      '--no-fund',
      '--loglevel=error',
      spec,
    ],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (res.status !== 0) {
    // Expected until release-config#205 publishes the package: warn and leave the release
    // exactly as Lerna produced it rather than failing a release over a missing tool.
    const why = (res.stderr || res.error?.message || '')
      .split('\n')
      .filter((l) => /npm (error|ERR!)/.test(l) && !/_logs\//.test(l))
      .slice(0, 2)
      .join(' | ');
    warn(
      `graduation-notes: could not install ${spec} — skipping aggregation (${why.trim()})`,
    );
    return null;
  }
  const bin = join(prefix, 'node_modules', name, 'bin.mjs');
  if (!existsSync(bin)) {
    warn(
      `graduation-notes: ${spec} installed but ${bin} is missing — skipping aggregation`,
    );
    return null;
  }
  return bin;
}

/* ------------------------------------------------------------------ api -- */

const API = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(
  /\/+$/,
  '',
);
const REPO = process.env.GITHUB_REPOSITORY;
const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';

function apiHeaders() {
  const h = {
    accept: 'application/vnd.github+json',
    'user-agent': 'side-graduation-notes-lerna',
    'x-github-api-version': '2022-11-28',
  };
  if (TOKEN) h.authorization = `Bearer ${TOKEN}`;
  return h;
}

async function getRelease(id) {
  const res = await fetch(`${API}/repos/${REPO}/releases/${id}`, {
    headers: apiHeaders(),
  });
  if (!res.ok) throw new Error(`GET release ${id} → HTTP ${res.status}`);
  return res.json();
}

async function patchReleaseBody(id, body) {
  const res = await fetch(`${API}/repos/${REPO}/releases/${id}`, {
    method: 'PATCH',
    headers: { ...apiHeaders(), 'content-type': 'application/json' },
    body: JSON.stringify({ body }),
  });
  if (!res.ok)
    throw new Error(
      `PATCH release ${id} → HTTP ${res.status} ${await res.text()}`,
    );
  return res.json();
}

/* ---------------------------------------------------------------- utils -- */

/** Tags Lerna created in this run: they point at the version commit, which is HEAD. */
function tagsAtHead() {
  try {
    return execFileSync('git', ['tag', '--points-at', 'HEAD'], {
      encoding: 'utf8',
    })
      .split('\n')
      .map((t) => t.trim())
      .filter(Boolean);
  } catch (e) {
    warn(
      `graduation-notes: git tag --points-at HEAD failed (${e.message}) — skipping`,
    );
    return [];
  }
}

/** '@scope/pkg@1.2.3' → { pkg: '@scope/pkg', version: '1.2.3' }; all 4 Lerna repos are independent. */
function splitTag(tag) {
  const i = tag.lastIndexOf('@');
  if (i <= 0) return null;
  const pkg = tag.slice(0, i);
  const version = tag.slice(i + 1);
  return /^\d+\.\d+\.\d+/.test(version) ? { pkg, version } : null;
}

/**
 * The version lerna diffed against, straight out of the body's compare link.
 * null when the link is absent or shaped unexpectedly — the engine's range check then decides.
 */
function compareFrom(body, pkg) {
  const m = COMPARE_RE.exec(String(body || ''));
  if (!m || !m[1].startsWith(`${pkg}@`)) return null;
  return m[1].slice(pkg.length + 1);
}

const isPrerelease = (v) => /^\d+\.\d+\.\d+-/.test(String(v || ''));

/** Drop lerna's sentinel line so the patched body doesn't contradict the notes below it. */
function stripSentinel(body) {
  return String(body || '')
    .split('\n')
    .filter((l) => !SENTINEL_RE.test(l))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** Count the same way on both sides of the assertion — that is what makes it meaningful. */
function bulletsAfterMarker(body, marker) {
  const i = String(body || '').indexOf(marker);
  if (i < 0) return -1;
  return body
    .slice(i)
    .replace(/\r\n/g, '\n')
    .split('\n')
    .filter((l) => /^\*\s+\S/.test(l)).length;
}

/* ----------------------------------------------------------------- main -- */

async function main() {
  if (!REPO) {
    warn('graduation-notes: GITHUB_REPOSITORY unset — skipping');
    return 0;
  }
  if (!TOKEN) {
    warn('graduation-notes: no GITHUB_TOKEN/GH_TOKEN — skipping');
    return 0;
  }

  const tags = tagsAtHead();
  if (!tags.length) {
    log(
      'graduation-notes: no tags at HEAD — nothing was published in this run',
    );
    return 0;
  }

  const engine = resolveEngine();
  if (!engine) return 0;

  const {
    MARKER_ID,
    fetchReleases,
    parseVersion,
    cmpVersions,
    sourcesInRange,
  } = await import(pathToFileURL(join(engine, '..', 'index.mjs')).href);

  let releases;
  try {
    releases = await fetchReleases({ repo: REPO, apiUrl: API, token: TOKEN });
  } catch (e) {
    // Same policy as the engine: never block on an unknown.
    warn(`graduation-notes: ${e.message} — skipping aggregation`);
    return 0;
  }

  const work = mkdtempSync(
    join(process.env.RUNNER_TEMP || tmpdir(), 'gradnotes-'),
  );
  const releasesFile = join(work, 'releases.json');
  writeFileSync(releasesFile, JSON.stringify(releases));

  const byTag = new Map(releases.map((r) => [r.tag_name, r]));
  const patched = [];
  let failures = 0;

  for (const tag of tags) {
    const split = splitTag(tag);
    if (!split) continue;
    const { pkg, version } = split;
    const rel = byTag.get(tag);
    if (!rel || rel.draft) {
      log(`graduation-notes: ${tag} — no published release, skipping`);
      continue;
    }
    if (rel.prerelease || isPrerelease(version)) continue;

    // Not gated on the sentinel: a graduation whose range DOES include the squash commit
    // publishes a collapsed one-entry body instead of the sentinel, and loses the prerelease
    // detail just the same (observed live on @side/test-monorepo-hello@11.2.0, 2026-07-30).
    // Whether there is anything to add is the engine's call — its nothing-new-vs-stable no-op
    // and sha-level dedupe decide, exactly as they do for Adapter A.
    if (!SENTINEL_RE.test(rel.body || '')) {
      log(`graduation-notes: ${tag} — collapsed body (no sentinel), letting the engine decide`);
    }
    // lastStable = the greatest stable release of THIS package below the graduated version.
    const cur = parseVersion(version);
    const lastStable = releases
      .filter((r) => !r.draft && r.tag_name.startsWith(`${pkg}@`))
      .map((r) => parseVersion(r.tag_name.slice(pkg.length + 1)))
      .filter((v) => v && !v.pre.length && cmpVersions(v, cur) < 0)
      .sort(cmpVersions)
      .pop();
    if (!lastStable) {
      log(`graduation-notes: ${tag} — no previous stable release, skipping`);
      continue;
    }

    const opts = {
      lastStable: lastStable.raw,
      newVersion: version,
      package: pkg,
    };
    const srcs = sourcesInRange(releases, opts);
    if (!srcs.length) {
      log(
        `graduation-notes: ${tag} — no prereleases between ${lastStable.raw} and ${version}`,
      );
      continue;
    }

    // A prerelease that is itself a bump-only sentinel carries nothing to recover (release-config:
    // its changelog path filter makes every -beta.N bump-only). Drop them from the engine's input
    // so they neither render as content nor count as unparseable sources.
    const noise = new Set(
      srcs.filter((r) => SENTINEL_RE.test(r.body || '')).map((r) => r.tag_name),
    );
    let payloadFile = releasesFile;
    if (noise.size) {
      if (noise.size === srcs.length) {
        log(
          `graduation-notes: ${tag} — every prerelease in range is itself bump-only, no-op`,
        );
        continue;
      }
      payloadFile = join(
        work,
        `releases-${noise.size}-${tag.replace(/[^\w.-]/g, '_')}.json`,
      );
      writeFileSync(
        payloadFile,
        JSON.stringify(releases.filter((r) => !noise.has(r.tag_name))),
      );
    }

    // A prerelease compare-from is the textbook graduation, but it is NOT required: real data has
    // bump-only stables whose compare-from is the last STABLE while their prereleases published
    // real notes (@side/fastify-pubsub@0.12.1 vs 0.12.1-alpha.0's #501) — the squash lands under a
    // sha/path lerna's own range filters out. Gating on the compare-from would skip those.
    const from = compareFrom(rel.body, pkg);
    if (from && !isPrerelease(from)) {
      log(
        `graduation-notes: ${tag} — bump-only although lerna compared against stable ${from}`,
      );
    }

    const stableBodyFile = join(
      work,
      `stable-${tag.replace(/[^\w.-]/g, '_')}.md`,
    );
    writeFileSync(stableBodyFile, stripSentinel(rel.body));

    const run = spawnSync(
      process.execPath,
      [
        engine,
        '--package',
        pkg,
        '--last',
        lastStable.raw,
        '--next',
        version,
        '--releases-file',
        payloadFile,
        '--stable-body-file',
        stableBodyFile,
        '--with-stable-body',
      ],
      { encoding: 'utf8', env: { ...process.env, GITHUB_TOKEN: TOKEN } },
    );
    if (run.stderr) process.stderr.write(run.stderr);

    if (run.status === 2) {
      error(
        `graduation-notes: ${tag} — prerelease sources found but unrenderable; body left empty`,
      );
      failures++;
      continue;
    }
    if (run.status !== 0) {
      error(`graduation-notes: ${tag} — engine exited ${run.status}`);
      failures++;
      continue;
    }
    const body = run.stdout || '';
    if (!body.trim()) {
      log(`graduation-notes: ${tag} — nothing to aggregate (no-op)`);
      continue;
    }

    if (process.env.GRADUATION_NOTES_DRY_RUN === '1') {
      log(`graduation-notes: DRY RUN — would patch ${tag} (release ${rel.id})`);
      process.stdout.write(`${body}\n`);
      continue;
    }

    try {
      await patchReleaseBody(rel.id, body);
    } catch (e) {
      error(`graduation-notes: ${tag} — ${e.message}`);
      failures++;
      continue;
    }
    patched.push({ tag, id: rel.id, body, from: lastStable.raw });
    log(
      `graduation-notes: ${tag} — patched (aggregated from ${lastStable.raw})`,
    );
  }

  // Guard 2 (design §4): re-read every patched release and prove the notes are actually there.
  for (const p of patched) {
    let live;
    try {
      live = await getRelease(p.id);
    } catch (e) {
      error(
        `graduation-notes: ${p.tag} — could not re-read the patched release: ${e.message}`,
      );
      failures++;
      continue;
    }
    const expected = bulletsAfterMarker(p.body, MARKER_ID);
    const actual = bulletsAfterMarker(live.body, MARKER_ID);
    if (actual < 0) {
      error(
        `graduation-notes: ${p.tag} — patched body has no ${MARKER_ID} marker`,
      );
      failures++;
      continue;
    }
    if (actual < expected) {
      error(
        `graduation-notes: ${p.tag} — published body has ${actual} aggregated entries, expected ${expected}`,
      );
      failures++;
      continue;
    }
    // GitHub returns bodies CRLF-normalised, so compare on \n.
    if (
      String(live.body).replace(/\r\n/g, '\n').trim() !==
      p.body.replace(/\r\n/g, '\n').trim()
    ) {
      error(
        `graduation-notes: ${p.tag} — published body differs from what was sent`,
      );
      failures++;
      continue;
    }
    log(
      `graduation-notes: ${p.tag} — assertion OK (${actual} aggregated entries)`,
    );
  }

  if (process.env.GITHUB_STEP_SUMMARY && patched.length) {
    const rows = patched
      .map((p) => `| \`${p.tag}\` | ${bulletsAfterMarker(p.body, MARKER_ID)} |`)
      .join('\n');
    writeFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      `\n### Graduation notes\n\n| Release | Aggregated entries |\n|---|---|\n${rows}\n`,
      { flag: 'a' },
    );
  }

  if (failures) {
    error(`graduation-notes: ${failures} release(s) could not be repaired`);
    return 1;
  }
  log(`graduation-notes: done — ${patched.length} release(s) patched`);
  return 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((e) => {
    error(`graduation-notes: ${e.stack || e.message}`);
    process.exitCode = 1;
  });

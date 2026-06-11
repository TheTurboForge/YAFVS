#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Browser-level TurboVAS runtime regression smoke using Playwright."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT_MS = 30_000
PLAYWRIGHT_NODE_PATHS = (
    "/home/turboforge/.local/nodejs/node-v22.22.3-linux-x64/lib/node_modules",
    "/home/turboforge/.local/share/turbovas-tools/playwright/node_modules",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def result(status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "summary": summary, "generated_at": now_iso(), "details": details}


def status_rank(status: str) -> int:
    return {"pass": 0, "warn": 1, "fail": 2}.get(status, 2)


def aggregate(findings: list[dict[str, Any]]) -> str:
    current = "pass"
    for item in findings:
        status = str(item.get("status", "fail"))
        if status_rank(status) > status_rank(current):
            current = status
    return current


def playwright_node_path_candidates() -> list[str]:
    candidates: list[str] = []
    for entry in os.environ.get("NODE_PATH", "").split(os.pathsep):
        if entry:
            candidates.append(entry)
    try:
        npm_root = subprocess.run(
            ["npm", "root", "-g"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
        if npm_root.returncode == 0 and npm_root.stdout.strip():
            candidates.append(npm_root.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass
    candidates.extend(PLAYWRIGHT_NODE_PATHS)

    seen: set[str] = set()
    existing: list[str] = []
    for candidate in candidates:
        path = str(Path(candidate).expanduser())
        if path in seen:
            continue
        seen.add(path)
        if (Path(path) / "playwright" / "package.json").is_file():
            existing.append(path)
    return existing


BROWSER_SCRIPT = r"""
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const password = process.env.TURBOVAS_BROWSER_SMOKE_PASSWORD || '';
const findings = [];
const artifacts = [];

function add(status, check, message, details = {}) {
  findings.push({ status, check, message, details });
}

function artifactPath(name) {
  return path.join(config.artifactDir, name);
}

async function screenshot(page, name) {
  const target = artifactPath(`${name}.png`);
  await page.screenshot({ path: target, fullPage: true }).catch(() => null);
  artifacts.push(target);
}

async function bodyText(page) {
  return await page.locator('body').innerText({ timeout: config.timeoutMs });
}

async function assertNoAppError(page, check) {
  const text = await bodyText(page);
  const bad = /An error occurred on this page|EntitiesContainer|Failure to receive response from manager daemon/i.test(text);
  add(bad ? 'fail' : 'pass', check, bad ? 'Page shows an application error.' : 'Page loaded without the GSA application error boundary.', { url: page.url() });
  return !bad;
}

async function gotoRoute(page, route, label) {
  const url = new URL(route, config.baseUrl).toString();
  await page.goto(url, { waitUntil: 'networkidle', timeout: config.timeoutMs });
  await screenshot(page, label);
  await assertNoAppError(page, `${label}.app-error`);
  return await bodyText(page);
}

async function fillFirst(page, selectors, value) {
  for (const selector of selectors) {
    const locator = page.locator(selector).first();
    if (await locator.count()) {
      await locator.fill(value);
      return true;
    }
  }
  return false;
}

async function login(page) {
  await page.goto(new URL('/login', config.baseUrl).toString(), { waitUntil: 'domcontentloaded', timeout: config.timeoutMs });
  await fillFirst(page, ['input[name="username"]', 'input#username', 'input[type="text"]'], config.username);
  await fillFirst(page, ['input[name="password"]', 'input#password', 'input[type="password"]'], password);
  const buttons = [
    page.getByRole('button', { name: /log\s*in|sign\s*in/i }).first(),
    page.locator('button[type="submit"]').first(),
  ];
  let clicked = false;
  for (const button of buttons) {
    if (await button.count()) {
      await button.click();
      clicked = true;
      break;
    }
  }
  if (!clicked) {
    await page.keyboard.press('Enter');
  }
  await page.waitForLoadState('networkidle', { timeout: config.timeoutMs }).catch(() => null);
  const text = await bodyText(page).catch(() => '');
  const loggedIn = !/username|password/i.test(text) || /tasks|scans|reports/i.test(text);
  add(loggedIn ? 'pass' : 'fail', 'browser.login', loggedIn ? 'Development operator login completed.' : 'Development operator login did not reach the application shell.', { url: page.url() });
  await screenshot(page, 'login-after-submit');
}

async function assertNoForbiddenText(page, routeName, forbidden) {
  const text = await bodyText(page);
  const found = forbidden.filter(item => item.test(text));
  add(found.length ? 'fail' : 'pass', `${routeName}.removed-controls`, found.length ? 'Removed controls or labels are visible.' : 'Removed controls and labels are absent.', { found: found.map(item => item.source) });
}

async function firstHref(page, matcher) {
  const hrefs = await page.locator('a[href]').evaluateAll(anchors => anchors.map(a => a.getAttribute('href')).filter(Boolean));
  return hrefs.find(href => matcher.test(href)) || null;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isScopeReportDetailUrl(url) {
  return /\/scopes\/[^/]+\/reports\/[^/?#]+/.test(new URL(url).pathname);
}

function isRawReportDetailUrl(url) {
  return /\/report\/[^/?#]+/.test(new URL(url).pathname);
}

async function clickTab(page, text, expectedUrl = () => true) {
  const before = page.url();
  const pattern = new RegExp(`^\\s*${escapeRegExp(text)}\\b`, 'i');
  const tabs = page.locator('[role="tab"]');
  const tabTexts = await tabs.evaluateAll(elements => elements.map(element => element.textContent || ''));
  const tabIndex = tabTexts.findIndex(value => pattern.test(value));
  if (tabIndex >= 0) {
    await tabs.nth(tabIndex).click();
    let selected = await page.waitForFunction(
      index => document.querySelectorAll('[role="tab"]')[index]?.getAttribute('aria-selected') === 'true',
      tabIndex,
      { timeout: config.timeoutMs },
    ).then(() => true).catch(() => false);
    if (!selected) {
      const url = new URL(page.url());
      url.searchParams.set('tab', String(tabIndex));
      await page.goto(url.toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
      selected = await page.waitForFunction(
        index => document.querySelectorAll('[role="tab"]')[index]?.getAttribute('aria-selected') === 'true',
        tabIndex,
        { timeout: config.timeoutMs },
      ).then(() => true).catch(() => false);
    }
    await page.waitForLoadState('networkidle', { timeout: config.timeoutMs }).catch(() => null);
    if (!expectedUrl(page.url())) {
      await page.goto(before, { waitUntil: 'networkidle', timeout: config.timeoutMs }).catch(() => null);
      return false;
    }
    return selected;
  }
  return false;
}

async function clickFirstResultRow(page) {
  const tableRows = page.locator('tbody tr');
  await tableRows.first().waitFor({ state: 'visible', timeout: Math.min(config.timeoutMs, 10_000) }).catch(() => null);
  const rowCount = await tableRows.count();
  if (rowCount) {
    await tableRows.first().click({ position: { x: 10, y: 10 } }).catch(() => null);
    await page.waitForTimeout(500);
    add('pass', 'scope-report.results-row-click', 'Clicked the first Results table row without triggering a page error.', { rowCount });
  } else {
    add(config.expectResultRow ? 'fail' : 'warn', 'scope-report.results-row-click', 'No Results table rows were available to click.', { url: page.url() });
  }
  await assertNoAppError(page, 'scope-report.results-after-row-click');
}

async function waitForMetricLabels(page) {
  await page.waitForFunction(
    () => /CVSS Load/i.test(document.body.innerText) && /Authenticated Scan Coverage/i.test(document.body.innerText),
    null,
    { timeout: config.timeoutMs },
  ).catch(() => null);
}

async function runForBaseUrl(baseUrl) {
  config.baseUrl = baseUrl;
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.setDefaultTimeout(config.timeoutMs);
  try {
    await login(page);

    await gotoRoute(page, '/reports', 'reports');
    await assertNoForbiddenText(page, 'reports', [/Delta Report/i, /Import Report/i]);

    await gotoRoute(page, '/tasks', 'tasks');
    await assertNoForbiddenText(page, 'tasks', [/Resume/i, /Task Wizard/i, /Advanced Task Wizard/i, /Import Task/i, /Delta Report/i]);

    await gotoRoute(page, '/scopes/reports', 'scope-reports');
    const detailHref = config.scopeReportPath || await firstHref(page, /\/scopes\/[^/]+\/reports\/[^/]+/);
    add(detailHref ? 'pass' : 'fail', 'scope-reports.detail-link', detailHref ? 'Found a canonical scope-report detail route.' : 'No canonical scope-report detail link found.', { href: detailHref, preferred: Boolean(config.scopeReportPath) });
    if (!detailHref) return;

    await page.goto(new URL(detailHref, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
    await screenshot(page, 'scope-report-detail');
    await assertNoAppError(page, 'scope-report-detail.app-error');
    const detailText = await bodyText(page);
    const requiredTabs = ['Information', 'Metrics', 'Results', 'Evidence Sources'];
    const missingTabs = requiredTabs.filter(tab => !detailText.includes(tab));
    add(missingTabs.length ? 'fail' : 'pass', 'scope-report-detail.tabs', missingTabs.length ? 'Scope-report detail is missing expected report-like tabs.' : 'Scope-report detail exposes expected report-like tabs.', { missing: missingTabs });

    const detailUrl = page.url();
    if (await clickTab(page, 'Metrics', isScopeReportDetailUrl)) {
      await waitForMetricLabels(page);
      await screenshot(page, 'scope-report-metrics-tab');
      const metricsText = await bodyText(page);
      const hasMetrics = /CVSS Load/i.test(metricsText) && /Authenticated Scan Coverage/i.test(metricsText);
      add(hasMetrics ? 'pass' : 'fail', 'scope-report.metrics-tab', hasMetrics ? 'Scope-report Metrics tab exposes CVSS Load and Authenticated Scan Coverage.' : 'Scope-report Metrics tab is missing expected metric labels.');
    } else {
      add('fail', 'scope-report.metrics-tab', 'Could not activate the Metrics tab.');
    }

    await page.goto(detailUrl, { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, 'Results', isScopeReportDetailUrl)) {
      await screenshot(page, 'scope-report-results-tab');
      await clickFirstResultRow(page);
    } else {
      add('fail', 'scope-report.results-tab', 'Could not activate the Results tab.');
    }

    await page.goto(detailUrl, { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, 'Evidence Sources', isScopeReportDetailUrl)) {
      await screenshot(page, 'scope-report-evidence-sources-tab');
      const rawReportHref = await firstHref(page, /\/report\//);
      add(rawReportHref ? 'pass' : 'fail', 'scope-report.evidence-raw-report-link', rawReportHref ? 'Evidence Sources contains a raw-report link.' : 'Evidence Sources does not contain a raw-report link.', { href: rawReportHref });
      if (rawReportHref) {
        await page.goto(new URL(rawReportHref, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
        await screenshot(page, 'raw-report-from-evidence-link');
        await assertNoAppError(page, 'raw-report-from-evidence-link.app-error');
        if (await clickTab(page, 'Metrics', isRawReportDetailUrl)) {
          await waitForMetricLabels(page);
          await screenshot(page, 'raw-report-metrics-tab');
          const rawMetricsText = await bodyText(page);
          const hasRawMetrics = /CVSS Load/i.test(rawMetricsText) && /Authenticated Scan Coverage/i.test(rawMetricsText);
          add(hasRawMetrics ? 'pass' : 'fail', 'raw-report.metrics-tab', hasRawMetrics ? 'Raw-report Metrics tab exposes CVSS Load and Authenticated Scan Coverage.' : 'Raw-report Metrics tab is missing expected metric labels.');
        } else {
          add('fail', 'raw-report.metrics-tab', 'Could not activate the raw-report Metrics tab.');
        }
      }
    } else {
      add('fail', 'scope-report.evidence-sources-tab', 'Could not activate the Evidence Sources tab.');
    }
  } finally {
    await context.close();
    await browser.close();
  }
}

(async () => {
  for (const baseUrl of config.baseUrls) {
    try {
      await runForBaseUrl(baseUrl);
    } catch (error) {
      add('fail', 'browser.exception', String(error && error.stack ? error.stack : error), { baseUrl });
    }
  }
  const status = findings.reduce((current, item) => {
    const rank = { pass: 0, warn: 1, fail: 2 };
    return rank[item.status] > rank[current] ? item.status : current;
  }, 'pass');
  const payload = {
    status,
    summary: status === 'pass' ? 'Browser runtime smoke passed.' : 'Browser runtime smoke found issues.',
    generated_at: new Date().toISOString(),
    findings,
    artifacts,
    metadata: { base_urls: config.baseUrls },
  };
  const output = artifactPath('browser-smoke.json');
  fs.writeFileSync(output, JSON.stringify(payload, null, 2) + '\n');
  payload.artifacts.push(output);
  console.log(JSON.stringify(payload));
})().catch(error => {
  const payload = {
    status: 'fail',
    summary: 'Browser runtime smoke crashed.',
    generated_at: new Date().toISOString(),
    findings: [{ status: 'fail', check: 'browser.crash', message: String(error && error.stack ? error.stack : error) }],
    artifacts,
    metadata: { base_urls: config.baseUrls },
  };
  console.log(JSON.stringify(payload));
  process.exit(1);
});
"""


def write_artifact(artifact_dir: Path, name: str, payload: dict[str, Any]) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def run_browser_smoke(args: argparse.Namespace) -> dict[str, Any]:
    artifact_dir = Path(args.artifact_dir).expanduser().resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    password = Path(args.password_file).read_text(encoding="utf-8").strip()
    node_paths = playwright_node_path_candidates()
    findings: list[dict[str, Any]] = []
    if not node_paths:
        payload = result("fail", "Playwright module was not found.", searched=list(PLAYWRIGHT_NODE_PATHS))
        payload["findings"] = [{"status": "fail", "check": "playwright.module", "message": "No Playwright node_modules path was found."}]
        payload["artifacts"] = [write_artifact(artifact_dir, "browser-smoke-failed.json", payload)]
        return payload

    script_path = artifact_dir / "browser-smoke.cjs"
    config_path = artifact_dir / "browser-smoke-config.json"
    script_path.write_text(BROWSER_SCRIPT, encoding="utf-8")
    config_path.write_text(
        json.dumps(
            {
                "artifactDir": str(artifact_dir),
                "baseUrls": args.base_url,
                "username": args.username,
                "timeoutMs": args.timeout_ms,
                "scopeReportPath": args.scope_report_path,
                "expectResultRow": args.expect_result_row,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["NODE_PATH"] = os.pathsep.join([*node_paths, env.get("NODE_PATH", "")]).rstrip(os.pathsep)
    env["TURBOVAS_BROWSER_SMOKE_PASSWORD"] = password
    completed = subprocess.run(
        ["node", str(script_path), str(config_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        timeout=max(60, (args.timeout_ms // 1000) * max(1, len(args.base_url)) * 8),
    )
    try:
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        payload = result(
            "fail",
            "Browser smoke did not return JSON.",
            exit_code=completed.returncode,
            output_tail=completed.stdout.splitlines()[-80:],
        )
        payload["findings"] = [{"status": "fail", "check": "browser.output", "message": "Browser smoke did not return parseable JSON."}]
        payload["artifacts"] = []
    payload.setdefault("artifacts", [])
    payload["artifacts"].extend([str(script_path), str(config_path)])
    payload.setdefault("findings", findings)
    payload["status"] = payload.get("status") if completed.returncode == 0 else "fail"
    write_artifact(artifact_dir, "browser-smoke-wrapper.json", payload)
    if str(artifact_dir / "browser-smoke-wrapper.json") not in payload["artifacts"]:
        payload["artifacts"].append(str(artifact_dir / "browser-smoke-wrapper.json"))
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", action="append", required=True, help="GSA base URL to test; may be repeated")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    parser.add_argument("--scope-report-path", help="preferred canonical scope-report detail path to exercise")
    parser.add_argument("--expect-result-row", action="store_true", help="fail if the selected scope report has no visible Results row")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = run_browser_smoke(args)
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload.get("status") in {"pass", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

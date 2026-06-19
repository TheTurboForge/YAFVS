#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deep browser-level TurboVAS runtime regression checks using Playwright."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime_browser_smoke import DEFAULT_TIMEOUT_MS, playwright_node_path_candidates


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def result(status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "summary": summary, "generated_at": now_iso(), "details": details}


def write_artifact(artifact_dir: Path, name: str, payload: dict[str, Any]) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


BROWSER_SCRIPT = r"""
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const password = process.env.TURBOVAS_BROWSER_REGRESSION_PASSWORD || '';
const findings = [];
const artifacts = [];
const network = [];
const pageErrors = [];
const consoleErrors = [];

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

async function assertNoAppError(page, check) {
  const text = await bodyText(page).catch(() => '');
  const bad = /An error occurred on this page|EntitiesContainer|Failure to receive response from manager daemon/i.test(text);
  add(bad ? 'fail' : 'pass', check, bad ? 'Page shows a GSA application error.' : 'Page has no GSA application error.', { url: page.url() });
  return !bad;
}

async function assertNotUnexpectedTasks(page, check, allowed = false) {
  const pathname = new URL(page.url()).pathname;
  const bad = pathname === '/tasks' && !allowed;
  add(bad ? 'fail' : 'pass', check, bad ? 'Navigation unexpectedly landed on /tasks.' : 'Navigation did not unexpectedly land on /tasks.', { url: page.url() });
  return !bad;
}

async function login(page) {
  await page.goto(new URL('/login', config.baseUrl).toString(), { waitUntil: 'domcontentloaded', timeout: config.timeoutMs });
  await fillFirst(page, ['input[name="username"]', 'input#username', 'input[type="text"]'], config.username);
  await fillFirst(page, ['input[name="password"]', 'input#password', 'input[type="password"]'], password);
  const loginButton = page.getByRole('button', { name: /log\s*in|sign\s*in/i }).first();
  if (await loginButton.count()) {
    await loginButton.click();
  } else if (await page.locator('button[type="submit"]').first().count()) {
    await page.locator('button[type="submit"]').first().click();
  } else {
    await page.keyboard.press('Enter');
  }
  await page.waitForLoadState('networkidle', { timeout: config.timeoutMs }).catch(() => null);
  await screenshot(page, 'login-after-submit');
  const text = await bodyText(page).catch(() => '');
  const loggedIn = !/username|password/i.test(text) || /tasks|scans|reports/i.test(text);
  add(loggedIn ? 'pass' : 'fail', 'browser.login', loggedIn ? 'Development operator login completed.' : 'Development operator login did not reach the application shell.', { url: page.url() });
}

async function gotoRoute(page, route, check) {
  await page.goto(new URL(route, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
  await screenshot(page, check.replace(/[^a-z0-9_-]+/gi, '-'));
  await assertNoAppError(page, `${check}.app-error`);
  await assertNotUnexpectedTasks(page, `${check}.not-tasks`, route === '/tasks');
}

async function clickTab(page, label) {
  const tabs = page.locator('[role="tab"]');
  const texts = await tabs.evaluateAll(elements => elements.map(element => element.textContent || ''));
  const index = texts.findIndex(text => new RegExp(`^\\s*${label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(text));
  if (index < 0) return false;
  await tabs.nth(index).click();
  await page.waitForLoadState('networkidle', { timeout: config.timeoutMs }).catch(() => null);
  await page.waitForTimeout(250);
  return true;
}

async function firstHref(page, matcher) {
  const hrefs = await page.locator('a[href]').evaluateAll(anchors => anchors.map(anchor => anchor.getAttribute('href')).filter(Boolean));
  return hrefs.find(href => matcher.test(href)) || null;
}

async function firstExpandedRowDetailHref(page, matcher) {
  const tableCount = await page.getByTestId('entities-table').count().catch(() => 0);
  if (!tableCount) return { href: null, reason: 'no-entities-table' };
  const toggleCount = await page.getByTestId('row-details-toggle').count().catch(() => 0);
  if (!toggleCount) return { href: null, reason: 'no-row-details-toggle' };

  const toggle = page.getByTestId('row-details-toggle').first();
  try {
    await toggle.scrollIntoViewIfNeeded({ timeout: config.timeoutMs });
    await toggle.click({ timeout: config.timeoutMs });
  } catch (error) {
    return { href: null, reason: 'row-details-toggle-click-failed', error: String(error) };
  }

  await page.waitForLoadState('networkidle', { timeout: config.timeoutMs }).catch(() => null);
  await page.waitForTimeout(300);
  const href = await firstHref(page, matcher);
  if (href) return { href, reason: 'expanded-row' };

  const detailHrefs = await page.getByTestId('details-link')
    .evaluateAll(anchors => anchors.map(anchor => anchor.getAttribute('href')).filter(Boolean))
    .catch(() => []);
  return { href: null, reason: detailHrefs.length ? 'details-link-mismatch' : 'no-details-link-after-expand', detailHrefs: detailHrefs.slice(0, 10) };
}

async function assertNativeSuccess(pathPattern, check) {
  const match = network.find(item => pathPattern.test(item.path) && item.status >= 200 && item.status < 300);
  add(match ? 'pass' : 'fail', check, match ? 'Expected native API response was observed.' : 'Expected native API response was not observed.', { pattern: String(pathPattern), responses: network.filter(item => pathPattern.test(item.path)).slice(-10) });
}

async function checkTopLevelRoute(page, route, check, nativePattern, detailPattern = null) {
  await gotoRoute(page, route, check);
  if (nativePattern) await assertNativeSuccess(nativePattern, `${check}.native-api`);
  if (!detailPattern) return;
  let detailHref = await firstHref(page, detailPattern);
  let linkSource = 'visible-page-link';
  let expandedDetails = null;
  if (!detailHref) {
    expandedDetails = await firstExpandedRowDetailHref(page, detailPattern);
    detailHref = expandedDetails.href;
    linkSource = expandedDetails.reason;
  }
  if (!detailHref) {
    add('warn', `${check}.detail-link`, 'No matching detail link was available from live data after checking visible and expanded row links.', { route, detailPattern: String(detailPattern), expandedDetails });
    return;
  }
  await page.goto(new URL(detailHref, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
  await screenshot(page, `${check}-detail`);
  const pathname = new URL(page.url()).pathname;
  const expected = detailPattern.test(pathname);
  add(expected ? 'pass' : 'fail', `${check}.detail-route`, expected ? 'Detail link landed on the intended route class.' : 'Detail link landed on an unexpected route.', { href: detailHref, pathname, linkSource });
  await assertNoAppError(page, `${check}.detail-app-error`);
  await assertNotUnexpectedTasks(page, `${check}.detail-not-tasks`);
}

async function clickFirstEnabledPager(page, direction) {
  const candidates = [
    page.getByRole('button', { name: new RegExp(direction, 'i') }).last(),
    page.locator(`[title="${direction}"]`).last(),
    page.locator(`button:has-text("${direction}")`).last(),
    page.locator(`a:has-text("${direction}")`).last(),
  ];
  for (const candidate of candidates) {
    if (!(await candidate.count())) continue;
    const disabled = await candidate.evaluate(element => element.disabled || element.getAttribute('aria-disabled') === 'true' || element.classList.contains('disabled')).catch(() => true);
    if (disabled) continue;
    await candidate.click();
    return true;
  }
  return false;
}

async function exercisePagination(page, check) {
  const beforePath = new URL(page.url()).pathname;
  let clicks = 0;
  for (let index = 0; index < 3; index += 1) {
    const clicked = await clickFirstEnabledPager(page, 'Next');
    if (!clicked) break;
    clicks += 1;
    await page.waitForLoadState('networkidle', { timeout: config.timeoutMs }).catch(() => null);
    await page.waitForTimeout(350);
    const afterPath = new URL(page.url()).pathname;
    if (afterPath !== beforePath) {
      add('fail', `${check}.route-stability`, 'Pagination changed the route path unexpectedly.', { beforePath, afterPath, url: page.url() });
      return;
    }
    await assertNoAppError(page, `${check}.page-${index + 1}.app-error`);
    await assertNotUnexpectedTasks(page, `${check}.page-${index + 1}.not-tasks`);
  }
  add(clicks ? 'pass' : 'warn', `${check}.pagination`, clicks ? 'Pagination Next stayed on the intended route.' : 'No enabled Next pagination control was available in live data.', { clicks, path: beforePath });
}

async function checkScopeReport(page) {
  await gotoRoute(page, '/scopes/reports', 'scope-reports');
  await assertNativeSuccess(/\/api\/v1\/scope-reports$/, 'scope-reports.native-api');
  const detailHref = config.scopeReportPath || await firstHref(page, /\/scopes\/[^/]+\/reports\/[^/]+/);
  add(detailHref ? 'pass' : 'fail', 'scope-report.detail-link', detailHref ? 'Found a scope-report detail link.' : 'No scope-report detail link was found.', { href: detailHref });
  if (!detailHref) return;
  await page.goto(new URL(detailHref, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
  await screenshot(page, 'scope-report-detail');
  await assertNoAppError(page, 'scope-report-detail.app-error');
  const detailPath = new URL(page.url()).pathname;

  const tabs = ['Information', 'Metrics', 'Results', 'Hosts', 'Ports', 'Applications', 'Operating Systems', 'CVEs', 'TLS Certificates', 'Error Messages', 'Evidence Sources'];
  const detailText = await bodyText(page).catch(() => '');
  const missing = tabs.filter(tab => !detailText.includes(tab));
  add(missing.length ? 'fail' : 'pass', 'scope-report.tabs', missing.length ? 'Scope-report detail is missing report-like tabs.' : 'Scope-report detail exposes report-like tabs.', { missing });

  if (await clickTab(page, 'Results')) {
    await screenshot(page, 'scope-report-results');
    await assertNativeSuccess(/\/api\/v1\/scopes\/[^/]+\/reports\/[^/]+\/results$/, 'scope-report.results-native-api');
    const badNested = await firstHref(page, /\/report\/[^/]+\/result\/[^/]+/);
    add(badNested ? 'fail' : 'pass', 'scope-report.result-evidence-link-shape', badNested ? 'Result evidence link uses an unsupported nested raw-report route.' : 'Result evidence links avoid unsupported nested raw-report routes.', { href: badNested });
    const resultHref = await firstHref(page, /^\/result\/[^/]+/);
    if (resultHref) {
      await page.goto(new URL(resultHref, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
      await screenshot(page, 'scope-report-result-evidence');
      const pathname = new URL(page.url()).pathname;
      add(/^\/result\/[^/]+$/.test(pathname) ? 'pass' : 'fail', 'scope-report.result-evidence-route', /^\/result\/[^/]+$/.test(pathname) ? 'Result evidence link opened the raw result detail route.' : 'Result evidence link opened the wrong route.', { resultHref, pathname });
      await assertNoAppError(page, 'scope-report.result-evidence-app-error');
      await assertNotUnexpectedTasks(page, 'scope-report.result-evidence-not-tasks');
      await page.goto(new URL(detailPath, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
      await clickTab(page, 'Results');
    } else {
      add(config.expectResultRow ? 'fail' : 'warn', 'scope-report.result-evidence-link', 'No direct raw result evidence link was available in live Results data.', { detailPath });
    }
    await exercisePagination(page, 'scope-report.results');
  } else {
    add('fail', 'scope-report.results-tab', 'Could not activate the Results tab.');
  }

  for (const tab of ['Hosts', 'Ports', 'CVEs', 'Error Messages']) {
    await page.goto(new URL(detailPath, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, tab)) {
      await screenshot(page, `scope-report-${tab.toLowerCase().replace(/\s+/g, '-')}`);
      await exercisePagination(page, `scope-report.${tab.toLowerCase().replace(/\s+/g, '-')}`);
    } else {
      add('warn', `scope-report.${tab}.tab`, `Could not activate ${tab} tab for pagination check.`);
    }
  }

  await page.goto(new URL(detailPath, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
  if (await clickTab(page, 'Evidence Sources')) {
    await screenshot(page, 'scope-report-evidence-sources');
    const rawReportHref = await firstHref(page, /^\/report\/[^/?#]+/);
    add(rawReportHref ? 'pass' : 'fail', 'scope-report.evidence-raw-report-link', rawReportHref ? 'Evidence Sources has a raw-report link.' : 'Evidence Sources lacks a raw-report link.', { href: rawReportHref });
    if (rawReportHref) {
      await page.goto(new URL(rawReportHref, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
      await screenshot(page, 'scope-report-evidence-raw-report');
      const pathname = new URL(page.url()).pathname;
      add(/^\/report\/[^/]+$/.test(pathname) ? 'pass' : 'fail', 'scope-report.evidence-raw-report-route', /^\/report\/[^/]+$/.test(pathname) ? 'Raw-report evidence link opened a raw report.' : 'Raw-report evidence link opened the wrong route.', { rawReportHref, pathname });
      await assertNoAppError(page, 'scope-report.evidence-raw-report-app-error');
    }
  } else {
    add('fail', 'scope-report.evidence-sources-tab', 'Could not activate Evidence Sources tab.');
  }
}

async function runForBaseUrl(baseUrl) {
  config.baseUrl = baseUrl;
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.setDefaultTimeout(config.timeoutMs);
  page.on('pageerror', error => pageErrors.push(String(error && error.stack ? error.stack : error)));
  page.on('console', message => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('response', async response => {
    try {
      const url = new URL(response.url());
      if (url.pathname.startsWith('/api/v1/')) {
        network.push({ path: url.pathname, query: url.search, status: response.status() });
      }
    } catch (_) {
      // Ignore non-URL browser-internal responses.
    }
  });
  try {
    await login(page);
    await checkTopLevelRoute(page, '/reports', 'raw-reports', /\/api\/v1\/reports$/, /^\/report\/[^/]+/);
    await checkTopLevelRoute(page, '/results', 'results', /\/api\/v1\/results$/, /^\/result\/[^/]+/);
    await checkTopLevelRoute(page, '/vulnerabilities', 'vulnerabilities', /\/api\/v1\/vulnerabilities$/, null);
    await checkTopLevelRoute(page, '/cves', 'cves', /\/api\/v1\/cves$/, /^\/cve\/[^/]+/);
    await checkTopLevelRoute(page, '/hosts', 'hosts', /\/api\/v1\/hosts$/, /^\/host\/[^/]+/);
    await checkTopLevelRoute(page, '/operating-systems', 'operating-systems', /\/api\/v1\/operating-systems$/, null);
    await checkTopLevelRoute(page, '/tls-certificates', 'tls-certificates', /\/api\/v1\/tls-certificates$/, null);
    await checkTopLevelRoute(page, '/scanners', 'scanners', /\/api\/v1\/scanners$/, null);
    await checkTopLevelRoute(page, '/targets', 'targets', /\/api\/v1\/targets$/, /^\/target\/[^/]+/);
    await checkTopLevelRoute(page, '/tasks', 'tasks', /\/api\/v1\/tasks$/, /^\/task\/[^/]+/);
    await checkTopLevelRoute(page, '/scopes', 'scopes', /\/api\/v1\/scopes$/, /^\/scopes\/[^/]+$/);
    await checkScopeReport(page);
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
  const nativeFailures = network.filter(item => item.status >= 400);
  if (nativeFailures.length) {
    add('fail', 'network.native-api-failures', 'One or more native API browser responses failed.', { failures: nativeFailures });
  } else {
    add('pass', 'network.native-api-failures', 'No failed native API browser responses were observed.');
  }
  if (pageErrors.length) {
    add('fail', 'browser.page-errors', 'Unhandled browser page errors were observed.', { errors: pageErrors });
  } else {
    add('pass', 'browser.page-errors', 'No unhandled browser page errors were observed.');
  }
  if (consoleErrors.length) {
    add('warn', 'browser.console-errors', 'Console error messages were observed.', { errors: consoleErrors.slice(0, 20), count: consoleErrors.length });
  } else {
    add('pass', 'browser.console-errors', 'No console error messages were observed.');
  }
  const status = findings.reduce((current, item) => {
    const rank = { pass: 0, warn: 1, fail: 2 };
    return rank[item.status] > rank[current] ? item.status : current;
  }, 'pass');
  const payload = {
    status,
    summary: status === 'pass' ? 'Deep browser regression passed.' : 'Deep browser regression found issues.',
    generated_at: new Date().toISOString(),
    findings,
    artifacts,
    network,
    metadata: { base_urls: config.baseUrls },
  };
  const output = artifactPath('browser-regression.json');
  fs.writeFileSync(output, JSON.stringify(payload, null, 2) + '\n');
  payload.artifacts.push(output);
  console.log(JSON.stringify(payload));
})().catch(error => {
  const payload = {
    status: 'fail',
    summary: 'Deep browser regression crashed.',
    generated_at: new Date().toISOString(),
    findings: [{ status: 'fail', check: 'browser.crash', message: String(error && error.stack ? error.stack : error) }],
    artifacts,
    network,
    metadata: { base_urls: config.baseUrls },
  };
  console.log(JSON.stringify(payload));
  process.exit(1);
});
"""


def run_browser_regression(args: argparse.Namespace) -> dict[str, Any]:
    artifact_dir = Path(args.artifact_dir).expanduser().resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    password = Path(args.password_file).read_text(encoding="utf-8").strip()
    node_paths = playwright_node_path_candidates()
    if not node_paths:
        payload = result("fail", "Playwright module was not found.", searched=[])
        payload["findings"] = [{"status": "fail", "check": "playwright.module", "message": "No Playwright node_modules path was found."}]
        payload["artifacts"] = [write_artifact(artifact_dir, "browser-regression-failed.json", payload)]
        return payload

    script_path = artifact_dir / "browser-regression.cjs"
    config_path = artifact_dir / "browser-regression-config.json"
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
    env["TURBOVAS_BROWSER_REGRESSION_PASSWORD"] = password
    completed = subprocess.run(
        ["node", str(script_path), str(config_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        timeout=max(120, (args.timeout_ms // 1000) * max(1, len(args.base_url)) * 16),
    )
    try:
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        payload = result(
            "fail",
            "Deep browser regression did not return JSON.",
            exit_code=completed.returncode,
            output_tail=completed.stdout.splitlines()[-120:],
        )
        payload["findings"] = [{"status": "fail", "check": "browser.output", "message": "Deep browser regression did not return parseable JSON."}]
        payload["artifacts"] = []
    payload.setdefault("artifacts", [])
    payload["artifacts"].extend([str(script_path), str(config_path)])
    payload["status"] = payload.get("status") if completed.returncode == 0 else "fail"
    write_artifact(artifact_dir, "browser-regression-wrapper.json", payload)
    if str(artifact_dir / "browser-regression-wrapper.json") not in payload["artifacts"]:
        payload["artifacts"].append(str(artifact_dir / "browser-regression-wrapper.json"))
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", action="append", required=True, help="GSA base URL to test; may be repeated")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    parser.add_argument("--scope-report-path", help="preferred canonical scope-report detail path to exercise")
    parser.add_argument("--expect-result-row", action="store_true", help="fail if the selected scope report has no Results evidence link")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = run_browser_regression(args)
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload.get("status") in {"pass", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

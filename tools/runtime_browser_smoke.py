#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Browser-level TurboVAS runtime regression smoke using Playwright."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT_MS = 30_000
ROUTES_ENV = "TURBOVAS_BROWSER_SMOKE_ROUTES"
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

async function screenshotContentEvidence(page) {
  return await page.evaluate(() => {
    const isVisible = element => {
      const style = window.getComputedStyle(element);
      if (style.visibility === 'hidden' || style.display === 'none' || Number(style.opacity) === 0) return false;
      const rect = element.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    };
    const visibleElements = Array.from(document.querySelectorAll('body *')).filter(isVisible);
    const contentElements = visibleElements.filter(element => element.matches('a, button, input, select, textarea, table, tbody tr, img, svg, canvas, [role="button"], [role="grid"], [role="table"], [role="tab"], [data-testid="entities-table"]'));
    const bodyText = (document.body?.innerText || '').replace(/\s+/g, ' ').trim();
    return {
      title: document.title || '',
      textLength: bodyText.length,
      textSample: bodyText.slice(0, 120),
      visibleElementCount: visibleElements.length,
      contentElementCount: contentElements.length,
      bodyChildCount: document.body ? document.body.children.length : 0,
      url: window.location.href,
    };
  }).catch(error => ({ error: String(error) }));
}

async function screenshot(page, name) {
  const target = artifactPath(`${name}.png`);
  try {
    await page.screenshot({ path: target, fullPage: true });
    artifacts.push(target);
  } catch (error) {
    add('warn', `${name}.screenshot`, 'Screenshot capture failed.', { artifact: target, error: String(error) });
    return;
  }
  const evidence = await screenshotContentEvidence(page);
  const emptyLooking = !evidence.error && evidence.textLength < 8 && evidence.contentElementCount === 0 && evidence.visibleElementCount < 4;
  if (emptyLooking) {
    add('warn', `${name}.screenshot-content`, 'Screenshot page looked empty or weak at capture time.', { artifact: target, evidence });
  }
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

async function gotoRoute(page, route, label, options = {}) {
  const url = new URL(route, config.baseUrl).toString();
  await page.goto(url, { waitUntil: options.waitUntil || 'networkidle', timeout: config.timeoutMs });
  if (options.readyText) {
    await page.waitForFunction(
      pattern => new RegExp(pattern, 'i').test(document.body?.innerText || ''),
      options.readyText,
      { timeout: config.timeoutMs },
    ).catch(() => null);
  }
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
  return loggedIn;
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

async function waitForNativeApiResponse(page, responses, matcher) {
  const deadline = Date.now() + config.timeoutMs;
  while (Date.now() < deadline) {
    const match = responses.find(item => matcher.test(item.path) && item.status >= 200 && item.status < 300);
    if (match) return match;
    await page.waitForTimeout(250);
  }
  return null;
}

async function waitForNativeItemId(page, responses, path) {
  const deadline = Date.now() + config.timeoutMs;
  while (Date.now() < deadline) {
    const match = responses.find(item => item.path === path && Array.isArray(item.itemIds) && item.itemIds.length > 0);
    if (match) return match.itemIds[0];
    await page.waitForTimeout(250);
  }
  return null;
}

async function assertNoPerSourceEvidenceSections(page, check) {
  const text = await bodyText(page);
  const found = /Evidence Source:/i.test(text);
  add(found ? 'fail' : 'pass', check, found ? 'Tab still renders per-source raw-report evidence sections.' : 'Tab renders as one aggregated scope-report collection.', { url: page.url() });
}

async function fetchNativeJsonWithBrowserToken(page, path) {
  return await page.evaluate(async requestPath => {
    const token = window.localStorage.getItem('token') || '';
    const separator = requestPath.includes('?') ? '&' : '?';
    const response = await fetch(`${requestPath}${separator}token=${encodeURIComponent(token)}`, {
      headers: { Accept: 'application/json' },
    });
    const text = await response.text();
    let body = null;
    try {
      body = JSON.parse(text);
    } catch (_) {
      // Preserve a short sample for diagnostics when a response is not JSON.
    }
    return { status: response.status, body, textSample: text.slice(0, 120) };
  }, path);
}

async function assertTagResourceNameProxy(page) {
  const taskNames = await fetchNativeJsonWithBrowserToken(page, '/api/v1/tags/resource-names/task?page_size=2&sort=name');
  const taskItems = Array.isArray(taskNames.body?.items) ? taskNames.body.items : null;
  add(
    taskNames.status === 200 && taskItems !== null ? 'pass' : 'fail',
    'tag.resource-names-native-api',
    taskNames.status === 200 && taskItems !== null ? 'Tag resource-name lookup loaded through same-origin native API.' : 'Tag resource-name lookup did not return a JSON item collection through same-origin native API.',
    { status: taskNames.status, total: taskNames.body?.page?.total ?? null, item_count: taskItems?.length ?? null, sample: taskItems?.[0] ?? taskNames.textSample },
  );

  const alertNames = await fetchNativeJsonWithBrowserToken(page, '/api/v1/tags/resource-names/alert?page_size=2&sort=name');
  const alertItems = Array.isArray(alertNames.body?.items) ? alertNames.body.items : null;
  add(
    alertNames.status === 200 && alertItems !== null ? 'pass' : 'fail',
    'tag.resource-names-alert-native-api',
    alertNames.status === 200 && alertItems !== null ? 'Alert resource-name lookup loaded through same-origin native API.' : 'Alert resource-name lookup did not return a JSON item collection through same-origin native API.',
    { status: alertNames.status, total: alertNames.body?.page?.total ?? null, item_count: alertItems?.length ?? null, sample: alertItems?.[0] ?? alertNames.textSample },
  );

  const denied = await fetchNativeJsonWithBrowserToken(page, '/api/v1/tags/resource-names/credential?page_size=1');
  add(
    [400, 404].includes(denied.status) ? 'pass' : 'fail',
    'tag.resource-names-credential-blocked',
    [400, 404].includes(denied.status) ? 'Credential resource-name lookup remains unavailable through the same-origin native proxy.' : 'Credential resource-name lookup unexpectedly returned through the same-origin native proxy.',
    { status: denied.status, message: denied.body?.error?.message || denied.textSample },
  );
}

async function assertAlertMetadataProxy(page) {
  const alerts = await fetchNativeJsonWithBrowserToken(page, '/api/v1/alerts?page_size=1&sort=name');
  const alertItems = Array.isArray(alerts.body?.items) ? alerts.body.items : null;
  const allowedKeys = new Set(['id', 'name', 'comment', 'owner', 'active', 'in_use', 'task_count', 'event', 'condition', 'method', 'method_data_redacted', 'filter', 'created_at', 'modified_at']);
  const forbiddenKeys = new Set(['alert_method_data', 'method_data', 'event_data', 'condition_data', 'credential', 'credentials', 'password', 'secret', 'token', 'url', 'host', 'hosts', 'path', 'email', 'message', 'certificate', 'cert']);
  const unexpected = [];
  const forbidden = [];
  for (const item of alertItems || []) {
    for (const key of Object.keys(item || {})) {
      if (!allowedKeys.has(key)) unexpected.push(key);
      if (forbiddenKeys.has(key)) forbidden.push(key);
    }
    if (item?.method_data_redacted !== true) forbidden.push('method_data_redacted_false');
  }
  const ok = alerts.status === 200 && alertItems !== null && unexpected.length === 0 && forbidden.length === 0;
  add(
    ok ? 'pass' : 'fail',
    'alert.metadata-native-api',
    ok ? 'Redacted Alerts metadata list loaded through same-origin native API.' : 'Alerts metadata native proxy returned unexpected or unredacted data.',
    { status: alerts.status, total: alerts.body?.page?.total ?? null, item_count: alertItems?.length ?? null, unexpected, forbidden, sample: alertItems?.[0] ?? alerts.textSample },
  );

  const detail = await fetchNativeJsonWithBrowserToken(page, '/api/v1/alerts/00000000-0000-0000-0000-000000000000');
  add(
    [400, 404].includes(detail.status) ? 'pass' : 'fail',
    'alert.detail-blocked-native-api',
    [400, 404].includes(detail.status) ? 'Alert detail remains unavailable through the same-origin native proxy.' : 'Alert detail unexpectedly returned through the same-origin native proxy.',
    { status: detail.status, message: detail.body?.error?.message || detail.textSample },
  );
}

function focusedRouteCatalog() {
  const specs = [
    { label: 'reports', path: '/reports', nativePath: '/api/v1/reports', nativeCheck: 'raw-report.list-native-api', nativePass: 'Raw-report list loaded through same-origin native API.', nativeFail: 'Raw-report list did not produce a successful same-origin native API response.', forbidden: [/Delta Report/i, /Import Report/i], aliases: ['raw-reports'] },
    { label: 'results', path: '/results', nativePath: '/api/v1/results', nativeCheck: 'result.list-native-api', nativePass: 'Top-level Results list loaded through same-origin native API.', nativeFail: 'Top-level Results list did not produce a successful same-origin native API response.' },
    { label: 'vulnerabilities', path: '/vulnerabilities', nativePath: '/api/v1/vulnerabilities', nativeCheck: 'vulnerability.list-native-api', nativePass: 'Top-level Vulnerabilities list loaded through same-origin native API.', nativeFail: 'Top-level Vulnerabilities list did not produce a successful same-origin native API response.' },
    { label: 'cves', path: '/cves', nativePath: '/api/v1/cves', nativeCheck: 'cve.list-native-api', nativePass: 'Security Information CVE list loaded through same-origin native API.', nativeFail: 'Security Information CVE list did not produce a successful same-origin native API response.' },
    { label: 'cpes', path: '/cpes', nativePath: '/api/v1/cpes', nativeCheck: 'cpe.list-native-api', nativePass: 'Security Information CPE list loaded through same-origin native API.', nativeFail: 'Security Information CPE list did not produce a successful same-origin native API response.' },
    { label: 'nvts', path: '/nvts', nativePath: '/api/v1/nvts', nativeCheck: 'nvt.list-native-api', nativePass: 'Security Information NVT list loaded through same-origin native API.', nativeFail: 'Security Information NVT list did not produce a successful same-origin native API response.', aliases: ['nvt'] },
    { label: 'operating-systems', path: '/operating-systems', nativePath: '/api/v1/operating-systems', nativeCheck: 'operating-system.list-native-api', nativePass: 'Top-level Operating Systems list loaded through same-origin native API.', nativeFail: 'Top-level Operating Systems list did not produce a successful same-origin native API response.' },
    { label: 'hosts', path: '/hosts', nativePath: '/api/v1/hosts', nativeCheck: 'host.list-native-api', nativePass: 'Top-level Hosts list loaded through same-origin native API.', nativeFail: 'Top-level Hosts list did not produce a successful same-origin native API response.' },
    { label: 'tls-certificates', path: '/tls-certificates', nativePath: '/api/v1/tls-certificates', nativeCheck: 'tls-certificate.list-native-api', nativePass: 'Top-level TLS Certificates list loaded through same-origin native API.', nativeFail: 'Top-level TLS Certificates list did not produce a successful same-origin native API response.' },
    { label: 'scanners', path: '/scanners', nativePath: '/api/v1/scanners', nativeCheck: 'scanner.list-native-api', nativePass: 'Top-level Scanners list loaded through same-origin native API.', nativeFail: 'Top-level Scanners list did not produce a successful same-origin native API response.' },
    { label: 'scan-configs', path: '/scan-configs', nativePath: '/api/v1/scan-configs', nativeCheck: 'scan-config.list-native-api', nativePass: 'Top-level Scan Configs list loaded through same-origin native API.', nativeFail: 'Top-level Scan Configs list did not produce a successful same-origin native API response.', aliases: ['scanconfigs'] },
    { label: 'filters', path: '/filters', nativePath: '/api/v1/filters', nativeCheck: 'filter.list-native-api', nativePass: 'Top-level Filters list loaded through same-origin native API.', nativeFail: 'Top-level Filters list did not produce a successful same-origin native API response.' },
    { label: 'alerts', path: '/alerts', nativePath: null, aliases: ['alert'] },
    { label: 'tags', path: '/tags', nativePath: '/api/v1/tags', nativeCheck: 'tag.list-native-api', nativePass: 'Top-level Tags list loaded through same-origin native API.', nativeFail: 'Top-level Tags list did not produce a successful same-origin native API response.' },
    { label: 'overrides', path: '/overrides', nativePath: '/api/v1/overrides', nativeCheck: 'override.list-native-api', nativePass: 'Top-level Overrides list loaded through same-origin native API.', nativeFail: 'Top-level Overrides list did not produce a successful same-origin native API response.' },
    { label: 'port-lists', path: '/port-lists', nativePath: '/api/v1/port-lists', nativeCheck: 'port-list.list-native-api', nativePass: 'Top-level Port Lists loaded through same-origin native API.', nativeFail: 'Top-level Port Lists did not produce a successful same-origin native API response.' },
    { label: 'schedules', path: '/schedules', nativePath: '/api/v1/schedules', nativeCheck: 'schedule.list-native-api', nativePass: 'Top-level Schedules loaded through same-origin native API.', nativeFail: 'Top-level Schedules did not produce a successful same-origin native API response.' },
    { label: 'report-formats', path: '/reportformats', nativePath: '/api/v1/report-formats', nativeCheck: 'report-format.list-native-api', nativePass: 'Top-level Report Formats loaded through same-origin native API.', nativeFail: 'Top-level Report Formats did not produce a successful same-origin native API response.', aliases: ['reportformats'] },
    { label: 'report-configs', path: '/reportconfigs', nativePath: '/api/v1/report-configs', nativeCheck: 'report-config.list-native-api', nativePass: 'Top-level Report Configs loaded through same-origin native API.', nativeFail: 'Top-level Report Configs did not produce a successful same-origin native API response.', aliases: ['reportconfigs'] },
    { label: 'targets', path: '/targets', nativePath: '/api/v1/targets', nativeCheck: 'target.list-native-api', nativePass: 'Target list loaded through same-origin native API.', nativeFail: 'Target list did not produce a successful same-origin native API response.' },
    { label: 'tasks', path: '/tasks', nativePath: '/api/v1/tasks', nativeCheck: 'task.list-native-api', nativePass: 'Task list loaded through same-origin native API.', nativeFail: 'Task list did not produce a successful same-origin native API response.', forbidden: [/Resume/i, /Task Wizard/i, /Advanced Task Wizard/i, /Import Task/i, /Delta Report/i] },
    { label: 'trashcan', path: '/trashcan', nativePath: '/api/v1/trashcan/summary', nativeCheck: 'trashcan.summary-native-api', nativePass: 'Trashcan counts summary loaded through same-origin native API.', nativeFail: 'Trashcan route did not produce a successful same-origin native API summary response.', aliases: ['trash'], waitUntil: 'domcontentloaded', readyText: 'Trashcan|Contents' },
    { label: 'scopes', path: '/scopes', nativePath: '/api/v1/scopes', nativeCheck: 'scope.list-native-api', nativePass: 'Scope list loaded through same-origin native API.', nativeFail: 'Scope list did not produce a successful same-origin native API response.' },
    { label: 'scope-reports', path: '/scopes/reports', nativePath: '/api/v1/scope-reports', nativeCheck: 'scope-report.list-native-api', nativePass: 'Scope-report list loaded through same-origin native API.', nativeFail: 'Scope-report list did not produce a successful same-origin native API response.', aliases: ['scopes/reports'] },
    { label: 'cert-bund-advisories', path: '/cert-bund-advisories', nativePath: '/api/v1/cert-bund-advisories', nativeCheck: 'cert-bund-advisory.list-native-api', nativePass: 'CERT-Bund Advisory list loaded through same-origin native API.', nativeFail: 'CERT-Bund Advisory list did not produce a successful same-origin native API response.', aliases: ['certbunds', 'cert-bund'] },
    { label: 'dfn-cert-advisories', path: '/dfn-cert-advisories', nativePath: '/api/v1/dfn-cert-advisories', nativeCheck: 'dfn-cert-advisory.list-native-api', nativePass: 'DFN-CERT Advisory list loaded through same-origin native API.', nativeFail: 'DFN-CERT Advisory list did not produce a successful same-origin native API response.', aliases: ['dfncerts', 'dfn-cert'] },
  ];
  const catalog = new Map();
  for (const spec of specs) {
    for (const alias of [spec.label, spec.path, ...(spec.aliases || [])]) {
      catalog.set(alias.toLowerCase().replace(/^\/+/, ''), spec);
      catalog.set(alias.toLowerCase(), spec);
    }
  }
  return catalog;
}

function routeLabelFromPath(value) {
  const pathname = value.split(/[?#]/)[0].replace(/^\/+|\/+$/g, '');
  return (pathname || 'root').replace(/[^A-Za-z0-9_-]+/g, '-');
}

function focusedRouteSpecs() {
  const catalog = focusedRouteCatalog();
  const seen = new Set();
  const specs = [];
  for (const rawValue of config.focusRoutes || []) {
    const raw = String(rawValue || '').trim();
    if (!raw) continue;
    let pathOrLabel = raw;
    try {
      if (/^https?:\/\//i.test(raw)) {
        const parsed = new URL(raw);
        pathOrLabel = `${parsed.pathname}${parsed.search}`;
      }
    } catch (_) {
      pathOrLabel = raw;
    }
    const key = pathOrLabel.toLowerCase().replace(/^\/+/, '');
    const catalogSpec = catalog.get(pathOrLabel.toLowerCase()) || catalog.get(key);
    const spec = catalogSpec || {
      label: routeLabelFromPath(pathOrLabel),
      path: pathOrLabel.startsWith('/') ? pathOrLabel : `/${pathOrLabel}`,
      nativePath: null,
      nativeCheck: null,
      nativePass: null,
      nativeFail: null,
    };
    const dedupeKey = `${spec.label}:${spec.path}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    specs.push(spec);
  }
  return specs;
}

async function validateFocusedRoute(page, nativeApiResponses, spec) {
  const startIndex = nativeApiResponses.length;
  await gotoRoute(page, spec.path, spec.label, { waitUntil: spec.waitUntil, readyText: spec.readyText });
  if (spec.forbidden) {
    await assertNoForbiddenText(page, spec.label, spec.forbidden);
  }
  const observed = nativeApiResponses.slice(startIndex).filter(item => item.path.startsWith('/api/v1/'));
  if (!spec.nativePath) {
    add('pass', `focused-route.${spec.label}`, 'Focused browser route loaded without a GSA application error.', { path: spec.path, observed_native_api_responses: observed });
    if (spec.label === 'alerts') {
      await assertAlertMetadataProxy(page);
    }
    return;
  }
  const nativeResponse = await waitForNativeApiResponse(page, nativeApiResponses, new RegExp(`^${escapeRegExp(spec.nativePath)}$`));
  add(
    nativeResponse ? 'pass' : 'fail',
    spec.nativeCheck,
    nativeResponse ? spec.nativePass : spec.nativeFail,
    { path: spec.path, responses: nativeApiResponses.filter(item => item.path === spec.nativePath), observed_native_api_responses: observed },
  );
  if (spec.label === 'tags') {
    await assertTagResourceNameProxy(page);
  }
}

async function runForBaseUrl(baseUrl) {
  config.baseUrl = baseUrl;
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.setDefaultTimeout(config.timeoutMs);
  const nativeApiResponses = [];
  page.on('response', response => {
    try {
      const url = new URL(response.url());
      if (url.pathname.startsWith('/api/v1/')) {
        const entry = { path: url.pathname, status: response.status() };
        nativeApiResponses.push(entry);
        if (['/api/v1/cves', '/api/v1/cpes', '/api/v1/nvts', '/api/v1/targets', '/api/v1/tasks', '/api/v1/scan-configs', '/api/v1/filters', '/api/v1/tags', '/api/v1/overrides', '/api/v1/port-lists', '/api/v1/schedules', '/api/v1/report-formats', '/api/v1/report-configs', '/api/v1/cert-bund-advisories', '/api/v1/dfn-cert-advisories'].includes(url.pathname)) {
          response.json().then(body => {
            entry.itemIds = Array.isArray(body?.items)
              ? body.items.map(item => item?.id).filter(Boolean)
              : [];
          }).catch(() => null);
        }
      }
    } catch (_) {
      // Ignore non-URL browser-internal responses.
    }
  });
  try {
    const loggedIn = await login(page);
    const shellText = await bodyText(page).catch(() => '');
    add(/TurboVAS/i.test(shellText) ? 'pass' : 'fail', 'browser.branding', /TurboVAS/i.test(shellText) ? 'Application shell exposes TurboVAS branding.' : 'Application shell does not expose TurboVAS branding.');
    if (!loggedIn) {
      return;
    }

    const focusedRoutes = focusedRouteSpecs();
    if (focusedRoutes.length) {
      add('pass', 'browser-smoke.route-focus', 'Focused browser route mode is active.', { routes: focusedRoutes.map(spec => ({ label: spec.label, path: spec.path, native_path: spec.nativePath || null })) });
      for (const route of focusedRoutes) {
        await validateFocusedRoute(page, nativeApiResponses, route);
      }
      return;
    }

    await gotoRoute(page, '/reports', 'reports');
    await assertNoForbiddenText(page, 'reports', [/Delta Report/i, /Import Report/i]);
    const nativeRawReports = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/reports$/);
    add(nativeRawReports ? 'pass' : 'fail', 'raw-report.list-native-api', nativeRawReports ? 'Raw-report list loaded through same-origin native API.' : 'Raw-report list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/reports') });

    await gotoRoute(page, '/results', 'results');
    const nativeResults = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/results$/);
    add(nativeResults ? 'pass' : 'fail', 'result.list-native-api', nativeResults ? 'Top-level Results list loaded through same-origin native API.' : 'Top-level Results list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/results') });

    await gotoRoute(page, '/vulnerabilities', 'vulnerabilities');
    const nativeVulnerabilities = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/vulnerabilities$/);
    add(nativeVulnerabilities ? 'pass' : 'fail', 'vulnerability.list-native-api', nativeVulnerabilities ? 'Top-level Vulnerabilities list loaded through same-origin native API.' : 'Top-level Vulnerabilities list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/vulnerabilities') });

    await gotoRoute(page, '/cves', 'cves');
    const nativeCves = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/cves$/);
    add(nativeCves ? 'pass' : 'fail', 'cve.list-native-api', nativeCves ? 'Security Information CVE list loaded through same-origin native API.' : 'Security Information CVE list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/cves') });
    const cveDetailId = await waitForNativeItemId(page, nativeApiResponses, '/api/v1/cves');
    add(cveDetailId ? 'pass' : 'warn', 'cve.detail-id', cveDetailId ? 'Found a CVE id from the native list response.' : 'No CVE id was available from the native list response.', { id: cveDetailId });
    if (cveDetailId) {
      await gotoRoute(page, `/cve/${cveDetailId}`, 'cve-detail');
      await assertNoAppError(page, 'cve-detail.app-error');
      const nativeCveDetail = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/cves\/CVE-[0-9]+-[0-9]+$/i);
      add(nativeCveDetail ? 'pass' : 'fail', 'cve.detail-native-api', nativeCveDetail ? 'Security Information CVE detail loaded through same-origin native API.' : 'Security Information CVE detail did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => /\/api\/v1\/cves\/CVE-[0-9]+-[0-9]+$/i.test(item.path)) });
    }

    await gotoRoute(page, '/cpes', 'cpes');
    const nativeCpes = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/cpes$/);
    add(nativeCpes ? 'pass' : 'fail', 'cpe.list-native-api', nativeCpes ? 'Security Information CPE list loaded through same-origin native API.' : 'Security Information CPE list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/cpes') });
    const cpeDetailId = await waitForNativeItemId(page, nativeApiResponses, '/api/v1/cpes');
    add(cpeDetailId ? 'pass' : 'warn', 'cpe.detail-id', cpeDetailId ? 'Found a CPE id from the native list response.' : 'No CPE id was available from the native list response.', { id: cpeDetailId });
    if (cpeDetailId) {
      await gotoRoute(page, `/cpe/${encodeURIComponent(cpeDetailId)}`, 'cpe-detail');
      await assertNoAppError(page, 'cpe-detail.app-error');
      const nativeCpeDetail = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/cpes\/(?:cpe%3A|cpe:)/i);
      add(nativeCpeDetail ? 'pass' : 'fail', 'cpe.detail-native-api', nativeCpeDetail ? 'Security Information CPE detail loaded through same-origin native API.' : 'Security Information CPE detail did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/api/v1/cpes/')) });
    }

    await gotoRoute(page, '/operating-systems', 'operating-systems');
    const nativeOperatingSystems = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/operating-systems$/);
    add(nativeOperatingSystems ? 'pass' : 'fail', 'operating-system.list-native-api', nativeOperatingSystems ? 'Top-level Operating Systems list loaded through same-origin native API.' : 'Top-level Operating Systems list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/operating-systems') });

    await gotoRoute(page, '/hosts', 'hosts');
    const nativeHosts = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/hosts$/);
    add(nativeHosts ? 'pass' : 'fail', 'host.list-native-api', nativeHosts ? 'Top-level Hosts list loaded through same-origin native API.' : 'Top-level Hosts list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/hosts') });

    await gotoRoute(page, '/tls-certificates', 'tls-certificates');
    const nativeTlsCertificates = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/tls-certificates$/);
    add(nativeTlsCertificates ? 'pass' : 'fail', 'tls-certificate.list-native-api', nativeTlsCertificates ? 'Top-level TLS Certificates list loaded through same-origin native API.' : 'Top-level TLS Certificates list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/tls-certificates') });

    await gotoRoute(page, '/scanners', 'scanners');
    const nativeScanners = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/scanners$/);
    add(nativeScanners ? 'pass' : 'fail', 'scanner.list-native-api', nativeScanners ? 'Top-level Scanners list loaded through same-origin native API.' : 'Top-level Scanners list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/scanners') });

    await gotoRoute(page, '/filters', 'filters');
    const nativeFilters = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/filters$/);
    add(nativeFilters ? 'pass' : 'fail', 'filter.list-native-api', nativeFilters ? 'Top-level Filters list loaded through same-origin native API.' : 'Top-level Filters list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/filters') });
    const filterDetailId = await waitForNativeItemId(page, nativeApiResponses, '/api/v1/filters');
    add(filterDetailId ? 'pass' : 'warn', 'filter.detail-id', filterDetailId ? 'Found a filter id from the native list response.' : 'No filter id was available from the native list response.', { id: filterDetailId });
    if (filterDetailId) {
      await gotoRoute(page, `/filter/${filterDetailId}`, 'filter-detail');
      await assertNoAppError(page, 'filter-detail.app-error');
      const nativeFilterDetail = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/filters\/[^/]+$/);
      add(nativeFilterDetail ? 'pass' : 'fail', 'filter.detail-native-api', nativeFilterDetail ? 'Filter detail loaded through same-origin native API.' : 'Filter detail did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => /\/api\/v1\/filters\/[^/]+$/.test(item.path)) });
    }

    await gotoRoute(page, '/port-lists', 'port-lists');
    const nativePortLists = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/port-lists$/);
    add(nativePortLists ? 'pass' : 'fail', 'port-list.list-native-api', nativePortLists ? 'Top-level Port Lists loaded through same-origin native API.' : 'Top-level Port Lists did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/port-lists') });
    const portListDetailId = await waitForNativeItemId(page, nativeApiResponses, '/api/v1/port-lists');
    add(portListDetailId ? 'pass' : 'warn', 'port-list.detail-id', portListDetailId ? 'Found a port-list id from the native list response.' : 'No port-list id was available from the native list response.', { id: portListDetailId });
    if (portListDetailId) {
      await gotoRoute(page, `/port-list/${portListDetailId}`, 'port-list-detail');
      await assertNoAppError(page, 'port-list-detail.app-error');
      const nativePortListDetail = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/port-lists\/[^/]+$/);
      add(nativePortListDetail ? 'pass' : 'fail', 'port-list.detail-native-api', nativePortListDetail ? 'Port List detail loaded through same-origin native API.' : 'Port List detail did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => /\/api\/v1\/port-lists\/[^/]+$/.test(item.path)) });
    }

    await gotoRoute(page, '/schedules', 'schedules');
    const nativeSchedules = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/schedules$/);
    add(nativeSchedules ? 'pass' : 'fail', 'schedule.list-native-api', nativeSchedules ? 'Top-level Schedules loaded through same-origin native API.' : 'Top-level Schedules did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/schedules') });
    const scheduleDetailId = await waitForNativeItemId(page, nativeApiResponses, '/api/v1/schedules');
    add(scheduleDetailId ? 'pass' : 'warn', 'schedule.detail-id', scheduleDetailId ? 'Found a schedule id from the native list response.' : 'No schedule id was available from the native list response.', { id: scheduleDetailId });
    if (scheduleDetailId) {
      await gotoRoute(page, `/schedule/${scheduleDetailId}`, 'schedule-detail');
      await assertNoAppError(page, 'schedule-detail.app-error');
      const nativeScheduleDetail = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/schedules\/[^/]+$/);
      add(nativeScheduleDetail ? 'pass' : 'fail', 'schedule.detail-native-api', nativeScheduleDetail ? 'Schedule detail loaded through same-origin native API.' : 'Schedule detail did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => /\/api\/v1\/schedules\/[^/]+$/.test(item.path)) });
    }

    await gotoRoute(page, '/reportformats', 'report-formats');
    const nativeReportFormats = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/report-formats$/);
    add(nativeReportFormats ? 'pass' : 'fail', 'report-format.list-native-api', nativeReportFormats ? 'Top-level Report Formats loaded through same-origin native API.' : 'Top-level Report Formats did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/report-formats') });
    const reportFormatDetailId = await waitForNativeItemId(page, nativeApiResponses, '/api/v1/report-formats');
    add(reportFormatDetailId ? 'pass' : 'warn', 'report-format.detail-id', reportFormatDetailId ? 'Found a report-format id from the native list response.' : 'No report-format id was available from the native list response.', { id: reportFormatDetailId });
    if (reportFormatDetailId) {
      await gotoRoute(page, `/report-format/${reportFormatDetailId}`, 'report-format-detail');
      await assertNoAppError(page, 'report-format-detail.app-error');
      const nativeReportFormatDetail = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/report-formats\/[^/]+$/);
      add(nativeReportFormatDetail ? 'pass' : 'fail', 'report-format.detail-native-api', nativeReportFormatDetail ? 'Report Format detail loaded through same-origin native API.' : 'Report Format detail did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => /\/api\/v1\/report-formats\/[^/]+$/.test(item.path)) });
    }

    await gotoRoute(page, '/targets', 'targets');
    const nativeTargets = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/targets$/);
    add(nativeTargets ? 'pass' : 'fail', 'target.list-native-api', nativeTargets ? 'Target list loaded through same-origin native API.' : 'Target list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/targets') });
    const targetDetailId = await waitForNativeItemId(page, nativeApiResponses, '/api/v1/targets');
    add(targetDetailId ? 'pass' : 'warn', 'target.detail-id', targetDetailId ? 'Found a target id from the native list response.' : 'No target id was available from the native list response.', { id: targetDetailId });
    if (targetDetailId) {
      await gotoRoute(page, `/target/${targetDetailId}`, 'target-detail');
      await assertNoAppError(page, 'target-detail.app-error');
      const nativeTargetDetail = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/targets\/[^/]+$/);
      add(nativeTargetDetail ? 'pass' : 'fail', 'target.detail-native-api', nativeTargetDetail ? 'Target detail loaded through same-origin native API.' : 'Target detail did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => /\/api\/v1\/targets\/[^/]+$/.test(item.path)) });
    }

    await gotoRoute(page, '/tasks', 'tasks');
    await assertNoForbiddenText(page, 'tasks', [/Resume/i, /Task Wizard/i, /Advanced Task Wizard/i, /Import Task/i, /Delta Report/i]);
    const nativeTasks = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/tasks$/);
    add(nativeTasks ? 'pass' : 'fail', 'task.list-native-api', nativeTasks ? 'Task list loaded through same-origin native API.' : 'Task list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/tasks') });
    const taskDetailId = await waitForNativeItemId(page, nativeApiResponses, '/api/v1/tasks');
    add(taskDetailId ? 'pass' : 'warn', 'task.detail-id', taskDetailId ? 'Found a task id from the native list response.' : 'No task id was available from the native list response.', { id: taskDetailId });
    if (taskDetailId) {
      await gotoRoute(page, `/task/${taskDetailId}`, 'task-detail');
      await assertNoAppError(page, 'task-detail.app-error');
      const nativeTaskDetail = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/tasks\/[^/]+$/);
      add(nativeTaskDetail ? 'pass' : 'fail', 'task.detail-native-api', nativeTaskDetail ? 'Task detail loaded through same-origin native API.' : 'Task detail did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => /\/api\/v1\/tasks\/[^/]+$/.test(item.path)) });
    }

    await gotoRoute(page, '/scopes', 'scopes');
    const nativeScopes = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/scopes$/);
    add(nativeScopes ? 'pass' : 'fail', 'scope.list-native-api', nativeScopes ? 'Scope list loaded through same-origin native API.' : 'Scope list did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path === '/api/v1/scopes') });

    await gotoRoute(page, '/scopes/reports', 'scope-reports');
    const detailHref = config.scopeReportPath || await firstHref(page, /\/scopes\/[^/]+\/reports\/[^/]+/);
    add(detailHref ? 'pass' : 'fail', 'scope-reports.detail-link', detailHref ? 'Found a canonical scope-report detail route.' : 'No canonical scope-report detail link found.', { href: detailHref, preferred: Boolean(config.scopeReportPath) });
    if (!detailHref) return;

    await page.goto(new URL(detailHref, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
    await screenshot(page, 'scope-report-detail');
    await assertNoAppError(page, 'scope-report-detail.app-error');
    const detailText = await bodyText(page);
    const requiredTabs = ['Information', 'Metrics', 'Results', 'Hosts', 'Ports', 'Applications', 'Operating Systems', 'CVEs', 'TLS Certificates', 'Error Messages', 'Evidence Sources'];
    const missingTabs = requiredTabs.filter(tab => !detailText.includes(tab));
    add(missingTabs.length ? 'fail' : 'pass', 'scope-report-detail.tabs', missingTabs.length ? 'Scope-report detail is missing expected report-like tabs.' : 'Scope-report detail exposes expected report-like tabs.', { missing: missingTabs });

    const detailUrl = page.url();
    if (await clickTab(page, 'Metrics', isScopeReportDetailUrl)) {
      await waitForMetricLabels(page);
      await screenshot(page, 'scope-report-metrics-tab');
      const metricsText = await bodyText(page);
      const hasMetrics = /CVSS Load/i.test(metricsText) && /Authenticated Scan Coverage/i.test(metricsText);
      add(hasMetrics ? 'pass' : 'fail', 'scope-report.metrics-tab', hasMetrics ? 'Scope-report Metrics tab exposes CVSS Load and Authenticated Scan Coverage.' : 'Scope-report Metrics tab is missing expected metric labels.');
      const nativeScopeMetrics = nativeApiResponses.find(item => /\/api\/v1\/scopes\/[^/]+\/reports\/[^/]+\/metrics$/.test(item.path) && item.status >= 200 && item.status < 300);
      add(nativeScopeMetrics ? 'pass' : 'fail', 'scope-report.metrics-native-api', nativeScopeMetrics ? 'Scope-report Metrics tab loaded through same-origin native API.' : 'Scope-report Metrics tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/metrics')) });
    } else {
      add('fail', 'scope-report.metrics-tab', 'Could not activate the Metrics tab.');
    }

    await page.goto(detailUrl, { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, 'Results', isScopeReportDetailUrl)) {
      await screenshot(page, 'scope-report-results-tab');
      await clickFirstResultRow(page);
      await assertNoPerSourceEvidenceSections(page, 'scope-report.results-aggregated-native-tab');
      const nativeScopeResults = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/scopes\/[^/]+\/reports\/[^/]+\/results$/);
      add(nativeScopeResults ? 'pass' : 'fail', 'scope-report.results-native-api', nativeScopeResults ? 'Scope-report Results tab loaded through same-origin native API.' : 'Scope-report Results tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/results')) });
    } else {
      add('fail', 'scope-report.results-tab', 'Could not activate the Results tab.');
    }

    await page.goto(detailUrl, { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, 'Hosts', isScopeReportDetailUrl)) {
      await screenshot(page, 'scope-report-hosts-tab');
      await assertNoAppError(page, 'scope-report-hosts-tab.app-error');
      await assertNoPerSourceEvidenceSections(page, 'scope-report.hosts-aggregated-native-tab');
      const nativeScopeHosts = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/scopes\/[^/]+\/reports\/[^/]+\/hosts$/);
      add(nativeScopeHosts ? 'pass' : 'fail', 'scope-report.hosts-native-api', nativeScopeHosts ? 'Scope-report Hosts tab loaded through same-origin native API.' : 'Scope-report Hosts tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/hosts')) });
    } else {
      add('fail', 'scope-report.hosts-tab', 'Could not activate the native Hosts tab.');
    }

    await page.goto(detailUrl, { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, 'Ports', isScopeReportDetailUrl)) {
      await screenshot(page, 'scope-report-ports-tab');
      await assertNoAppError(page, 'scope-report-ports-tab.app-error');
      await assertNoPerSourceEvidenceSections(page, 'scope-report.ports-aggregated-native-tab');
      const nativeScopePorts = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/scopes\/[^/]+\/reports\/[^/]+\/ports$/);
      add(nativeScopePorts ? 'pass' : 'fail', 'scope-report.ports-native-api', nativeScopePorts ? 'Scope-report Ports tab loaded through same-origin native API.' : 'Scope-report Ports tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/ports')) });
    } else {
      add('fail', 'scope-report.ports-tab', 'Could not activate the native Ports tab.');
    }

    await page.goto(detailUrl, { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, 'Applications', isScopeReportDetailUrl)) {
      await screenshot(page, 'scope-report-applications-tab');
      await assertNoAppError(page, 'scope-report-applications-tab.app-error');
      await assertNoPerSourceEvidenceSections(page, 'scope-report.applications-aggregated-native-tab');
      const nativeScopeApplications = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/scopes\/[^/]+\/reports\/[^/]+\/applications$/);
      add(nativeScopeApplications ? 'pass' : 'fail', 'scope-report.applications-native-api', nativeScopeApplications ? 'Scope-report Applications tab loaded through same-origin native API.' : 'Scope-report Applications tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/applications')) });
    } else {
      add('fail', 'scope-report.applications-tab', 'Could not activate the native Applications tab.');
    }

    await page.goto(detailUrl, { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, 'Operating Systems', isScopeReportDetailUrl)) {
      await screenshot(page, 'scope-report-operating-systems-tab');
      await assertNoAppError(page, 'scope-report-operating-systems-tab.app-error');
      await assertNoPerSourceEvidenceSections(page, 'scope-report.operating-systems-aggregated-native-tab');
      const nativeScopeOperatingSystems = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/scopes\/[^/]+\/reports\/[^/]+\/operating-systems$/);
      add(nativeScopeOperatingSystems ? 'pass' : 'fail', 'scope-report.operating-systems-native-api', nativeScopeOperatingSystems ? 'Scope-report Operating Systems tab loaded through same-origin native API.' : 'Scope-report Operating Systems tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/operating-systems')) });
    } else {
      add('fail', 'scope-report.operating-systems-tab', 'Could not activate the native Operating Systems tab.');
    }

    await page.goto(detailUrl, { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, 'CVEs', isScopeReportDetailUrl)) {
      await screenshot(page, 'scope-report-cves-tab');
      await assertNoAppError(page, 'scope-report-cves-tab.app-error');
      await assertNoPerSourceEvidenceSections(page, 'scope-report.cves-aggregated-native-tab');
      const nativeScopeCves = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/scopes\/[^/]+\/reports\/[^/]+\/cves$/);
      add(nativeScopeCves ? 'pass' : 'fail', 'scope-report.cves-native-api', nativeScopeCves ? 'Scope-report CVEs tab loaded through same-origin native API.' : 'Scope-report CVEs tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/cves')) });
    } else {
      add('fail', 'scope-report.cves-tab', 'Could not activate the native CVEs tab.');
    }

    await page.goto(detailUrl, { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, 'TLS Certificates', isScopeReportDetailUrl)) {
      await screenshot(page, 'scope-report-tls-certificates-tab');
      await assertNoAppError(page, 'scope-report-tls-certificates-tab.app-error');
      await assertNoPerSourceEvidenceSections(page, 'scope-report.tls-certificates-aggregated-native-tab');
      const nativeScopeTlsCertificates = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/scopes\/[^/]+\/reports\/[^/]+\/tls-certificates$/);
      add(nativeScopeTlsCertificates ? 'pass' : 'fail', 'scope-report.tls-certificates-native-api', nativeScopeTlsCertificates ? 'Scope-report TLS Certificates tab loaded through same-origin native API.' : 'Scope-report TLS Certificates tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/tls-certificates')) });
    } else {
      add('fail', 'scope-report.tls-certificates-tab', 'Could not activate the native TLS Certificates tab.');
    }

    await page.goto(detailUrl, { waitUntil: 'networkidle', timeout: config.timeoutMs });
    if (await clickTab(page, 'Error Messages', isScopeReportDetailUrl)) {
      await screenshot(page, 'scope-report-errors-tab');
      await assertNoAppError(page, 'scope-report-errors-tab.app-error');
      await assertNoPerSourceEvidenceSections(page, 'scope-report.errors-aggregated-native-tab');
      const nativeScopeErrors = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/scopes\/[^/]+\/reports\/[^/]+\/errors$/);
      add(nativeScopeErrors ? 'pass' : 'fail', 'scope-report.errors-native-api', nativeScopeErrors ? 'Scope-report Error Messages tab loaded through same-origin native API.' : 'Scope-report Error Messages tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/errors')) });
    } else {
      add('fail', 'scope-report.errors-tab', 'Could not activate the native Error Messages tab.');
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
        if (await clickTab(page, 'Results', isRawReportDetailUrl)) {
          await screenshot(page, 'raw-report-results-tab');
          await assertNoAppError(page, 'raw-report-results-tab.app-error');
          const nativeRawResults = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/reports\/[^/]+\/results$/);
          add(nativeRawResults ? 'pass' : 'fail', 'raw-report.results-native-api', nativeRawResults ? 'Raw-report Results tab loaded through same-origin native API.' : 'Raw-report Results tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/results')) });
        } else {
          add('fail', 'raw-report.results-tab', 'Could not activate the raw-report Results tab.');
        }
        if (await clickTab(page, 'Hosts', isRawReportDetailUrl)) {
          await screenshot(page, 'raw-report-hosts-tab');
          await assertNoAppError(page, 'raw-report-hosts-tab.app-error');
          const nativeRawHosts = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/reports\/[^/]+\/hosts$/);
          add(nativeRawHosts ? 'pass' : 'fail', 'raw-report.hosts-native-api', nativeRawHosts ? 'Raw-report Hosts tab loaded through same-origin native API.' : 'Raw-report Hosts tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/hosts')) });
        } else {
          add('fail', 'raw-report.hosts-tab', 'Could not activate the raw-report Hosts tab.');
        }
        if (await clickTab(page, 'Ports', isRawReportDetailUrl)) {
          await screenshot(page, 'raw-report-ports-tab');
          await assertNoAppError(page, 'raw-report-ports-tab.app-error');
          const nativeRawPorts = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/reports\/[^/]+\/ports$/);
          add(nativeRawPorts ? 'pass' : 'fail', 'raw-report.ports-native-api', nativeRawPorts ? 'Raw-report Ports tab loaded through same-origin native API.' : 'Raw-report Ports tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/ports')) });
        } else {
          add('fail', 'raw-report.ports-tab', 'Could not activate the raw-report Ports tab.');
        }
        if (await clickTab(page, 'Applications', isRawReportDetailUrl)) {
          await screenshot(page, 'raw-report-applications-tab');
          await assertNoAppError(page, 'raw-report-applications-tab.app-error');
          const nativeRawApplications = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/reports\/[^/]+\/applications$/);
          add(nativeRawApplications ? 'pass' : 'fail', 'raw-report.applications-native-api', nativeRawApplications ? 'Raw-report Applications tab loaded through same-origin native API.' : 'Raw-report Applications tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/applications')) });
        } else {
          add('fail', 'raw-report.applications-tab', 'Could not activate the raw-report Applications tab.');
        }
        if (await clickTab(page, 'Operating Systems', isRawReportDetailUrl)) {
          await screenshot(page, 'raw-report-operating-systems-tab');
          await assertNoAppError(page, 'raw-report-operating-systems-tab.app-error');
          const nativeRawOperatingSystems = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/reports\/[^/]+\/operating-systems$/);
          add(nativeRawOperatingSystems ? 'pass' : 'fail', 'raw-report.operating-systems-native-api', nativeRawOperatingSystems ? 'Raw-report Operating Systems tab loaded through same-origin native API.' : 'Raw-report Operating Systems tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/operating-systems')) });
        } else {
          add('fail', 'raw-report.operating-systems-tab', 'Could not activate the raw-report Operating Systems tab.');
        }
        if (await clickTab(page, 'CVEs', isRawReportDetailUrl)) {
          await screenshot(page, 'raw-report-cves-tab');
          await assertNoAppError(page, 'raw-report-cves-tab.app-error');
          const nativeRawCves = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/reports\/[^/]+\/cves$/);
          add(nativeRawCves ? 'pass' : 'fail', 'raw-report.cves-native-api', nativeRawCves ? 'Raw-report CVEs tab loaded through same-origin native API.' : 'Raw-report CVEs tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/cves')) });
        } else {
          add('fail', 'raw-report.cves-tab', 'Could not activate the raw-report CVEs tab.');
        }
        if (await clickTab(page, 'TLS Certificates', isRawReportDetailUrl)) {
          await screenshot(page, 'raw-report-tls-certificates-tab');
          await assertNoAppError(page, 'raw-report-tls-certificates-tab.app-error');
          const nativeRawTlsCertificates = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/reports\/[^/]+\/tls-certificates$/);
          add(nativeRawTlsCertificates ? 'pass' : 'fail', 'raw-report.tls-certificates-native-api', nativeRawTlsCertificates ? 'Raw-report TLS Certificates tab loaded through same-origin native API.' : 'Raw-report TLS Certificates tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/tls-certificates')) });
        } else {
          add('fail', 'raw-report.tls-certificates-tab', 'Could not activate the raw-report TLS Certificates tab.');
        }
        if (await clickTab(page, 'Error Messages', isRawReportDetailUrl)) {
          await screenshot(page, 'raw-report-errors-tab');
          await assertNoAppError(page, 'raw-report-errors-tab.app-error');
          const nativeRawErrors = await waitForNativeApiResponse(page, nativeApiResponses, /\/api\/v1\/reports\/[^/]+\/errors$/);
          add(nativeRawErrors ? 'pass' : 'fail', 'raw-report.errors-native-api', nativeRawErrors ? 'Raw-report Error Messages tab loaded through same-origin native API.' : 'Raw-report Error Messages tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/errors')) });
        } else {
          add('fail', 'raw-report.errors-tab', 'Could not activate the raw-report Error Messages tab.');
        }
        if (await clickTab(page, 'Metrics', isRawReportDetailUrl)) {
          await waitForMetricLabels(page);
          await screenshot(page, 'raw-report-metrics-tab');
          const rawMetricsText = await bodyText(page);
          const hasRawMetrics = /CVSS Load/i.test(rawMetricsText) && /Authenticated Scan Coverage/i.test(rawMetricsText);
          add(hasRawMetrics ? 'pass' : 'fail', 'raw-report.metrics-tab', hasRawMetrics ? 'Raw-report Metrics tab exposes CVSS Load and Authenticated Scan Coverage.' : 'Raw-report Metrics tab is missing expected metric labels.');
          const nativeRawMetrics = nativeApiResponses.find(item => /\/api\/v1\/reports\/[^/]+\/metrics$/.test(item.path) && item.status >= 200 && item.status < 300);
          add(nativeRawMetrics ? 'pass' : 'fail', 'raw-report.metrics-native-api', nativeRawMetrics ? 'Raw-report Metrics tab loaded through same-origin native API.' : 'Raw-report Metrics tab did not produce a successful same-origin native API response.', { responses: nativeApiResponses.filter(item => item.path.includes('/metrics')) });
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


def split_route_values(values: list[str]) -> list[str]:
    routes: list[str] = []
    for value in values:
        routes.extend(part for part in re.split(r"[,\s]+", value.strip()) if part)
    return routes


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
    focus_routes = split_route_values([os.environ.get(ROUTES_ENV, ""), *(args.route or [])])
    config_path.write_text(
        json.dumps(
            {
                "artifactDir": str(artifact_dir),
                "baseUrls": args.base_url,
                "username": args.username,
                "timeoutMs": args.timeout_ms,
                "scopeReportPath": args.scope_report_path,
                "expectResultRow": args.expect_result_row,
                "focusRoutes": focus_routes,
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
    parser.add_argument("--route", action="append", help=f"focus the browser smoke on one route label or path; may be repeated, or set {ROUTES_ENV}=route1,route2")
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

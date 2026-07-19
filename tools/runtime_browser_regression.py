#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
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
const password = process.env.YAFVS_BROWSER_REGRESSION_PASSWORD || '';
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

async function entityTableState(page) {
  const text = await bodyText(page).catch(() => '');
  const emptyText = /No\s+[^.\n]+\s+available|No\s+data|No\s+[^.\n]+\s+found/i.test(text);
  const table = page.getByTestId('entities-table');
  const tableCount = await table.count().catch(() => 0);
  const rowCount = tableCount
    ? await table.first().locator('tbody tr').count().catch(() => 0)
    : 0;
  const toggleCount = await page.getByTestId('row-details-toggle').count().catch(() => 0);
  const detailLinkCount = await page.getByTestId('details-link').count().catch(() => 0);
  return { tableCount, rowCount, toggleCount, detailLinkCount, emptyText };
}

function noLiveDetailReason(state) {
  if (state.emptyText) return 'no-live-detail-data';
  if (state.tableCount && state.rowCount === 0) return 'no-live-detail-rows';
  return null;
}

function noLivePaginationReason(state) {
  if (state.emptyText) return 'no-live-pagination-data';
  if (state.tableCount && state.rowCount === 0) return 'no-live-pagination-rows';
  return null;
}

async function paginationRanges(page) {
  const text = await bodyText(page).catch(() => '');
  return [...text.matchAll(/\b(\d+)\s*-\s*(\d+)\s+of\s+(\d+)\b/g)]
    .map(match => ({ first: Number(match[1]), last: Number(match[2]), total: Number(match[3]), text: match[0] }));
}

async function assertCoherentPaginationCounts(page, check) {
  const ranges = await paginationRanges(page);
  const state = await entityTableState(page);
  if (!ranges.length) {
    if (!state.tableCount && !state.rowCount && !state.toggleCount && !state.detailLinkCount) {
      add('pass', `${check}.pagination-counts`, 'No standard entity-table pagination text was found; count coherence check is not applicable for this table.', { reason: 'no-standard-pagination-text', state });
      return ranges;
    }
    const reason = noLivePaginationReason(state) || 'selector-failure-no-pagination-text';
    add(reason.startsWith('selector-failure') ? 'warn' : 'pass', `${check}.pagination-counts`, reason.startsWith('selector-failure') ? 'No pagination text was found for a row-bearing table. Selector coverage may need an update.' : 'No live rows or data were available; pagination count check was skipped.', { reason, state });
    return ranges;
  }
  const badRanges = ranges.filter(range => range.total > 0 && (range.first < 1 || range.last < range.first || range.last > range.total));
  add(badRanges.length ? 'fail' : 'pass', `${check}.pagination-counts`, badRanges.length ? 'Pagination text contains an incoherent non-empty range.' : 'Pagination text contains coherent non-empty ranges.', { ranges, badRanges });
  return ranges;
}

async function firstExpandedRowDetailHref(page, matcher) {
  const state = await entityTableState(page);
  const noLiveReason = noLiveDetailReason(state);
  if (noLiveReason) {
    return { href: null, reason: noLiveReason, state };
  }
  if (!state.tableCount) {
    return { href: null, reason: 'selector-failure-no-entities-table', state };
  }
  if (!state.toggleCount) {
    const reason = state.detailLinkCount
      ? 'selector-failure-visible-details-link-mismatch'
      : 'selector-failure-no-row-details-toggle';
    return { href: null, reason, state };
  }

  const toggle = page.getByTestId('row-details-toggle').first();
  try {
    await toggle.scrollIntoViewIfNeeded({ timeout: config.timeoutMs });
    await toggle.click({ timeout: config.timeoutMs });
  } catch (error) {
    return { href: null, reason: 'selector-failure-row-details-toggle-click-failed', error: String(error), state };
  }

  await page.waitForLoadState('networkidle', { timeout: config.timeoutMs }).catch(() => null);
  await page.waitForTimeout(300);
  const href = await firstHref(page, matcher);
  if (href) return { href, reason: 'expanded-row' };

  const detailHrefs = await page.getByTestId('details-link')
    .evaluateAll(anchors => anchors.map(anchor => anchor.getAttribute('href')).filter(Boolean))
    .catch(() => []);
  return { href: null, reason: detailHrefs.length ? 'selector-failure-expanded-details-link-mismatch' : 'selector-failure-no-details-link-after-expand', detailHrefs: detailHrefs.slice(0, 10), state };
}

async function assertNativeSuccess(pathPattern, check) {
  const match = network.find(item => pathPattern.test(item.path) && item.status >= 200 && item.status < 300);
  add(match ? 'pass' : 'fail', check, match ? 'Expected native API response was observed.' : 'Expected native API response was not observed.', { pattern: String(pathPattern), responses: network.filter(item => pathPattern.test(item.path)).slice(-10) });
}

async function checkTopLevelRoute(page, route, check, nativePattern, detailPattern = null, detailNativePattern = null) {
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
    const noLiveDetail = expandedDetails && String(expandedDetails.reason || '').startsWith('no-live-detail');
    add(noLiveDetail ? 'pass' : 'warn', `${check}.detail-link`, noLiveDetail ? 'No live detail rows or data were available; detail-link route check was skipped.' : 'Detail rows existed, but no matching detail link was available after checking visible and expanded row links.', { route, detailPattern: String(detailPattern), expandedDetails });
    return;
  }
  await page.goto(new URL(detailHref, config.baseUrl).toString(), { waitUntil: 'networkidle', timeout: config.timeoutMs });
  await screenshot(page, `${check}-detail`);
  const pathname = new URL(page.url()).pathname;
  const expected = detailPattern.test(pathname);
  add(expected ? 'pass' : 'fail', `${check}.detail-route`, expected ? 'Detail link landed on the intended route class.' : 'Detail link landed on an unexpected route.', { href: detailHref, pathname, linkSource });
  if (detailNativePattern) await assertNativeSuccess(detailNativePattern, `${check}.detail-native-api`);
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
  let candidateCount = 0;
  let disabledCount = 0;
  for (const candidate of candidates) {
    const count = await candidate.count();
    if (!count) continue;
    candidateCount += count;
    const disabled = await candidate.evaluate(element => element.disabled || element.getAttribute('aria-disabled') === 'true' || element.classList.contains('disabled')).catch(() => true);
    if (disabled) {
      disabledCount += 1;
      continue;
    }
    await candidate.click();
    return { clicked: true, candidateCount, disabledCount };
  }
  return { clicked: false, candidateCount, disabledCount, reason: candidateCount ? 'single-page-no-enabled-next' : 'selector-failure-no-pagination-control' };
}

async function exercisePagination(page, check) {
  const beforePath = new URL(page.url()).pathname;
  await assertCoherentPaginationCounts(page, check);
  let clicks = 0;
  let finalPager = null;
  for (let index = 0; index < 3; index += 1) {
    const pager = await clickFirstEnabledPager(page, 'Next');
    if (!pager.clicked) {
      finalPager = pager;
      break;
    }
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
    await assertCoherentPaginationCounts(page, `${check}.page-${index + 1}`);
  }
  if (clicks) {
    add('pass', `${check}.pagination`, 'Pagination Next stayed on the intended route.', { clicks, path: beforePath });
    return;
  }
  const state = await entityTableState(page);
  const noLiveReason = noLivePaginationReason(state);
  const reason = noLiveReason || (finalPager && finalPager.reason === 'single-page-no-enabled-next'
    ? 'single-page-no-enabled-next'
    : 'selector-failure-no-pagination-control');
  const selectorFailure = reason.startsWith('selector-failure');
  const message = selectorFailure
    ? 'Rows were present, but no pagination control was found; selector coverage may need an update.'
    : reason === 'single-page-no-enabled-next'
      ? 'No enabled Next pagination control was available because the live data appears to fit on one page; pagination was skipped.'
      : 'No live rows or data were available; pagination was skipped.';
  add(selectorFailure ? 'warn' : 'pass', `${check}.pagination`, message, { clicks, path: beforePath, reason, pager: finalPager, state });
}

async function checkVulnerabilitiesRoute(page) {
  await gotoRoute(page, '/vulnerabilities', 'vulnerabilities');
  await assertNativeSuccess(/\/api\/v1\/vulnerabilities$/, 'vulnerabilities.native-api');
  await assertCoherentPaginationCounts(page, 'vulnerabilities');

  const beforeUrl = page.url();
  const state = await entityTableState(page);
  const noLiveReason = noLiveDetailReason(state);
  if (noLiveReason) {
    add('pass', 'vulnerabilities.inline-details', 'No live vulnerability rows were available; inline detail check was skipped.', { reason: noLiveReason, state });
  } else if (!state.toggleCount) {
    add('fail', 'vulnerabilities.inline-details', 'Vulnerability rows were present, but no row-detail toggle was available.', { state });
  } else {
    const toggle = page.getByTestId('row-details-toggle').first();
    await toggle.scrollIntoViewIfNeeded({ timeout: config.timeoutMs });
    await toggle.click({ timeout: config.timeoutMs });
    await page.waitForLoadState('networkidle', { timeout: config.timeoutMs }).catch(() => null);
    await page.waitForTimeout(300);
    await screenshot(page, 'vulnerabilities-inline-details');
    const afterUrl = page.url();
    const text = await bodyText(page).catch(() => '');
    const hasInlineDetails = /\bOID\b/.test(text) && /1\.3\.6\.1\.4\.1\.25623/.test(text);
    add(afterUrl === beforeUrl ? 'pass' : 'fail', 'vulnerabilities.inline-details-route', afterUrl === beforeUrl ? 'Clicking a vulnerability row title stayed on the list route.' : 'Clicking a vulnerability row title navigated away instead of expanding inline.', { beforeUrl, afterUrl });
    add(hasInlineDetails ? 'pass' : 'fail', 'vulnerabilities.inline-details-content', hasInlineDetails ? 'Clicking a vulnerability row title exposed inline vulnerability detail content.' : 'Clicking a vulnerability row title did not expose inline vulnerability detail content.', { textSample: text.slice(0, 1000) });
  }

  await exercisePagination(page, 'vulnerabilities');
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
      await assertNativeSuccess(/\/api\/v1\/results\/[0-9a-fA-F-]{36}$/, 'scope-report.result-evidence-native-api');
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
    await checkTopLevelRoute(page, '/results', 'results', /\/api\/v1\/results$/, /^\/result\/[^/]+/, /\/api\/v1\/results\/[0-9a-fA-F-]{36}$/);
    await checkVulnerabilitiesRoute(page);
    await checkTopLevelRoute(page, '/cves', 'cves', /\/api\/v1\/cves$/, /^\/cve\/[^/]+/);
    await checkTopLevelRoute(page, '/cpes', 'cpes', /\/api\/v1\/cpes$/, /^\/cpe\/[^/]+/);
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
    env["YAFVS_BROWSER_REGRESSION_PASSWORD"] = password
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

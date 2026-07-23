#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Browser-level credential lifecycle and download smoke for the YAFVS runtime."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from runtime_browser_smoke import DEFAULT_TIMEOUT_MS, playwright_node_path_candidates


CREDENTIAL_CLEANUP_POLICY = r"""
function retainOwnedFixture(fixtures, fixture) {
  return fixtures
    .filter(existing =>
      existing.id !== fixture.id || existing.baseUrl !== fixture.baseUrl)
    .concat([fixture]);
}

function fixturesForBaseUrl(fixtures, baseUrl) {
  return fixtures.filter(fixture => fixture.baseUrl === baseUrl);
}

function releaseOwnedFixture(fixtures, fixture) {
  return fixtures.filter(existing =>
    existing.id !== fixture.id || existing.baseUrl !== fixture.baseUrl);
}

function credentialCleanupDecision(fixture, trashItems, liveResult) {
  if (!fixture || typeof fixture.id !== 'string' || typeof fixture.name !== 'string'
      || typeof fixture.ownershipMarker !== 'string'
      || !Array.isArray(trashItems)) {
    return {action: 'identity-mismatch', owned: []};
  }
  const owned = trashItems.filter(item =>
    item && item.entity_type === 'credential' && item.id === fixture.id);
  if (owned.length === 0) {
    if (trashItems.length !== 0) {
      return {action: 'identity-mismatch', owned};
    }
    if (liveResult === undefined) {
      return {action: 'verify-live', owned};
    }
    if (!liveResult || !liveResult.ok) {
      return {action: 'live-unverified', owned};
    }
    if (liveResult.item !== null) {
      return {action: 'live-present', owned};
    }
    return {action: 'absent', owned};
  }
  if (trashItems.length !== 1
      || owned.length !== 1
      || owned[0].name !== fixture.name
      || owned[0].comment !== fixture.ownershipMarker) {
    return {action: 'identity-mismatch', owned};
  }
  return {action: 'purge', owned};
}
"""


BROWSER_SCRIPT = r"""
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const { chromium } = require('playwright');

const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const loginPassword = process.env.YAFVS_CREDENTIAL_SMOKE_LOGIN_PASSWORD || '';
const credentialPassword = process.env.YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD || '';
const findings = [];
const artifacts = [];
const MAX_DECLARED_DOWNLOAD_BYTES = 64 * 1024 * 1024;
""" + CREDENTIAL_CLEANUP_POLICY + r"""
const statePath = artifactPath('credential-smoke-state.json');
let ownedFixtures = Array.isArray(config.cleanupFixtures)
  ? config.cleanupFixtures.filter(fixture => fixture && fixture.name && fixture.kind)
  : [];
const recoveryFixtures = [...ownedFixtures];
const DOWNLOAD_CONTRACTS = {
  key: {
    title: 'Download Public Key',
    contentType: 'application/key',
    extension: 'pub',
  },
};
const REMOVED_DOWNLOAD_TITLES = [
  'Download Windows Executable (.exe)',
  'Download RPM (.rpm) Package',
  'Download Debian (.deb) Package',
];

function add(status, check, message, details = {}) {
  findings.push({status, check, message, details});
}

function safeError(error) {
  return String(error && error.stack ? error.stack : error)
    .replace(/([?&](?:token|access_token|session|session_token|auth_token|jwt)=)[^&\s)]+/gi, '$1[redacted]');
}

function safeStoredUrl(value) {
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}`;
  } catch {
    return '[invalid-url]';
  }
}

function artifactPath(name) {
  return path.join(config.artifactDir, name);
}

function persistOwnedFixtures() {
  fs.writeFileSync(
    statePath,
    JSON.stringify({fixtures: ownedFixtures}, null, 2) + '\n',
    {mode: 0o600},
  );
  fs.chmodSync(statePath, 0o600);
  if (!artifacts.includes(statePath)) artifacts.push(statePath);
}

function recordOwnedFixture(fixture) {
  ownedFixtures = retainOwnedFixture(ownedFixtures, fixture);
  persistOwnedFixtures();
}

function forgetOwnedFixture(fixture) {
  ownedFixtures = releaseOwnedFixture(ownedFixtures, fixture);
  persistOwnedFixtures();
}

async function screenshot(page, name) {
  const target = artifactPath(`${name}.png`);
  await page.screenshot({path: target, fullPage: true}).catch(() => null);
  artifacts.push(target);
}

async function bodyText(page) {
  return await page.locator('body').innerText({timeout: config.timeoutMs});
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

function declaredContentLength(headers) {
  const raw = headers['content-length'];
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

function forwardedAuthHeaders(headers) {
  const forwarded = {
    accept: '*/*',
    'accept-encoding': 'identity',
  };
  for (const name of ['authorization', 'cookie', 'x-yafvs-token', 'user-agent']) {
    if (typeof headers[name] === 'string' && headers[name]) {
      forwarded[name] = headers[name];
    }
  }
  return forwarded;
}

async function captureDownloadRequest(page, action, format) {
  const pattern = '**/gmp?*';
  let timer;
  let resolveCapture;
  let rejectCapture;
  const captured = new Promise((resolve, reject) => {
    resolveCapture = resolve;
    rejectCapture = reject;
    timer = setTimeout(
      () => reject(new Error(`Timed out while capturing ${format} credential request.`)),
      config.timeoutMs,
    );
  });
  const handler = async route => {
    const request = route.request();
    try {
      const url = new URL(request.url());
      if (url.searchParams.get('cmd') === 'download_credential'
          && url.searchParams.get('package_format') === format) {
        const headers = await request.allHeaders();
        clearTimeout(timer);
        resolveCapture({url: request.url(), headers});
        await route.abort('blockedbyclient');
        return;
      }
    } catch {
      // Non-matching requests continue unchanged.
    }
    await route.continue();
  };
  await page.route(pattern, handler);
  try {
    await action.click();
    return await captured;
  } catch (error) {
    clearTimeout(timer);
    rejectCapture(error);
    throw error;
  } finally {
    await page.unroute(pattern, handler);
  }
}

async function boundedAuthenticatedGet(urlValue, sourceHeaders) {
  const url = new URL(urlValue);
  const transport = url.protocol === 'https:' ? https : http;
  return await new Promise((resolve, reject) => {
    const request = transport.request(url, {
      method: 'GET',
      headers: forwardedAuthHeaders(sourceHeaders),
      rejectUnauthorized: false,
    }, response => {
      const declaredLength = declaredContentLength(response.headers);
      if (declaredLength === null
          || declaredLength > MAX_DECLARED_DOWNLOAD_BYTES) {
        response.destroy();
        reject(new Error('Credential response omitted a safe Content-Length or exceeded the characterization cap.'));
        return;
      }
      const chunks = [];
      let received = 0;
      response.on('data', chunk => {
        received += chunk.length;
        if (received > MAX_DECLARED_DOWNLOAD_BYTES) {
          request.destroy(new Error('Credential response exceeded the characterization cap while streaming.'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        resolve({
          status: response.statusCode || 0,
          headers: response.headers,
          declaredLength,
          bytes: Buffer.concat(chunks, received),
        });
      });
      response.on('error', reject);
    });
    request.setTimeout(config.timeoutMs, () => {
      request.destroy(new Error('Credential response exceeded its bounded streaming timeout.'));
    });
    request.on('error', reject);
    request.end();
  });
}

async function clickFirst(page, candidates) {
  for (const candidate of candidates) {
    if (await candidate.count()) {
      await candidate.click();
      return true;
    }
  }
  return false;
}

async function assertNoCredentialNameError(page, check) {
  const text = await bodyText(page).catch(() => '');
  const hasNameError = /Name must be at least one character long|A NAME is required/i.test(text);
  add(hasNameError ? 'fail' : 'pass', check, hasNameError ? 'Credential dialog still reports an empty-name validation error.' : 'No empty-name validation error is visible.');
  return !hasNameError;
}

async function credentialRow(page, credentialName) {
  return page.locator('tbody tr').filter({
    has: page.getByText(credentialName, {exact: true}),
  }).first();
}

async function credentialRowVisible(page, credentialName) {
  const row = await credentialRow(page, credentialName);
  return await row.count() > 0 && await row.isVisible().catch(() => false);
}

function isCredentialListResponse(response) {
  try {
    const url = new URL(response.url());
    return response.request().method() === 'GET'
      && url.pathname.endsWith('/api/v1/credentials')
      && response.status() === 200;
  } catch {
    return false;
  }
}

async function credentialIdFromResponse(response, credentialName) {
  if (!response) return null;
  const payload = await response.json().catch(() => null);
  const matches = payload && Array.isArray(payload.items)
    ? payload.items.filter(item => item && item.name === credentialName && typeof item.id === 'string')
    : [];
  return matches.length === 1
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(matches[0].id)
    ? matches[0].id
    : null;
}

async function deleteNativeTrashCredential(page, credentialId) {
  return await page.evaluate(async id => {
    const token = globalThis.localStorage.getItem('token');
    const jwt = globalThis.localStorage.getItem('jwt');
    const response = await fetch(
      new URL(`/api/v1/credentials/${encodeURIComponent(id)}/trash`, globalThis.location.origin),
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          ...(token ? {'X-YAFVS-Token': token} : {}),
          ...(jwt ? {Authorization: `Bearer ${jwt}`} : {}),
        },
      },
    );
    return {ok: response.ok, status: response.status};
  }, credentialId);
}

async function deleteNativeLiveCredential(page, credentialId) {
  return await page.evaluate(async id => {
    const token = globalThis.localStorage.getItem('token');
    const jwt = globalThis.localStorage.getItem('jwt');
    const response = await fetch(
      new URL(`/api/v1/credentials/${encodeURIComponent(id)}`, globalThis.location.origin),
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          ...(token ? {'X-YAFVS-Token': token} : {}),
          ...(jwt ? {Authorization: `Bearer ${jwt}`} : {}),
        },
      },
    );
    return {ok: response.ok, status: response.status};
  }, credentialId);
}

async function fetchNativeTrashCredential(page, credentialId) {
  return await page.evaluate(async id => {
    const token = globalThis.localStorage.getItem('token');
    const jwt = globalThis.localStorage.getItem('jwt');
    const headers = {
      Accept: 'application/json',
      ...(token ? {'X-YAFVS-Token': token} : {}),
      ...(jwt ? {Authorization: `Bearer ${jwt}`} : {}),
    };
    const url = new URL('/api/v1/trashcan/items', globalThis.location.origin);
    url.searchParams.set('id', id);
    url.searchParams.set('page_size', '2');
    url.searchParams.set('sort', 'id');
    if (token) url.searchParams.set('token', token);
    url.searchParams.set('_smoke_nonce', String(Date.now()));
    const response = await fetch(url, {
      cache: 'no-store',
      credentials: 'include',
      headers,
    });
    if (!response.ok) {
      return {ok: false, status: response.status, items: []};
    }
    const payload = await response.json().catch(() => null);
    return payload && Array.isArray(payload.items)
      ? {ok: true, status: response.status, items: payload.items}
      : {ok: false, status: response.status, items: []};
  }, credentialId);
}

async function fetchNativeLiveCredential(page, credentialId) {
  return await page.evaluate(async id => {
    const token = globalThis.localStorage.getItem('token');
    const jwt = globalThis.localStorage.getItem('jwt');
    const url = new URL(
      `/api/v1/credentials/${encodeURIComponent(id)}`,
      globalThis.location.origin,
    );
    if (token) url.searchParams.set('token', token);
    url.searchParams.set('_smoke_nonce', String(Date.now()));
    const response = await fetch(url, {
      cache: 'no-store',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        ...(token ? {'X-YAFVS-Token': token} : {}),
        ...(jwt ? {Authorization: `Bearer ${jwt}`} : {}),
      },
    });
    if (response.status === 404) {
      return {ok: true, status: response.status, item: null};
    }
    const item = response.ok ? await response.json().catch(() => null) : null;
    return {ok: response.ok && Boolean(item), status: response.status, item};
  }, credentialId);
}

async function login(page) {
  await page.goto(new URL('/login', config.baseUrl).toString(), {waitUntil: 'domcontentloaded', timeout: config.timeoutMs});
  await fillFirst(page, ['input[name="username"]', 'input#username', 'input[type="text"]'], config.username);
  await fillFirst(page, ['input[name="password"]', 'input#password', 'input[type="password"]'], loginPassword);
  await clickFirst(page, [
    page.getByRole('button', {name: /log\s*in|sign\s*in/i}).first(),
    page.locator('button[type="submit"]').first(),
  ]) || await page.keyboard.press('Enter');
  await page.waitForLoadState('networkidle', {timeout: config.timeoutMs}).catch(() => null);
  const text = await bodyText(page).catch(() => '');
  const loggedIn = /scans|tasks|reports|credentials/i.test(text) && !/login failed/i.test(text);
  add(loggedIn ? 'pass' : 'fail', 'credential-smoke.login', loggedIn ? 'Development operator login completed.' : 'Development operator login did not reach the application shell.', {url: safeStoredUrl(page.url())});
  await screenshot(page, 'login-after-submit');
}

async function gotoStable(page, route) {
  await page.goto(new URL(route, config.baseUrl).toString(), {
    waitUntil: 'domcontentloaded',
    timeout: config.timeoutMs,
  });
  await page
    .waitForLoadState('networkidle', {
      timeout: Math.min(config.timeoutMs, 5000),
    })
    .catch(() => null);
  await page.locator('body').waitFor({
    state: 'visible',
    timeout: config.timeoutMs,
  });
}

async function selectCredentialType(page, label) {
  const select = page.getByLabel(/^Type$/i).first();
  if (!(await select.count())) return false;
  await select.click();
  const option = page.getByRole('option', {name: label, exact: true}).first();
  if (!(await option.count())) return false;
  await option.click();
  return true;
}

async function createCredential(page, fixture) {
  await gotoStable(page, '/credentials');
  if (await credentialRowVisible(page, fixture.name)) {
    add('fail', `credential-smoke.${fixture.kind}.collision`, 'Refusing to create or delete a credential because the disposable fixture name already exists.', {credentialName: fixture.name});
    return null;
  }
  await screenshot(page, `credentials-before-create-${fixture.kind}-${config.urlIndex}`);
  const newClicked = await clickFirst(page, [
    page.getByTitle('New Credential').first(),
    page.getByRole('button', {name: /new credential/i}).first(),
  ]);
  add(newClicked ? 'pass' : 'fail', `credential-smoke.${fixture.kind}.new-button`, newClicked ? 'Opened the New Credential dialog.' : 'Could not find the New Credential action.');
  if (!newClicked) return null;

  await page.locator('input[name="name"]').first().waitFor({state: 'visible', timeout: config.timeoutMs});
  if (fixture.typeLabel) {
    const selected = await selectCredentialType(page, fixture.typeLabel);
    add(selected ? 'pass' : 'fail', `credential-smoke.${fixture.kind}.type`, selected ? `Selected ${fixture.typeLabel}.` : `Could not select ${fixture.typeLabel}.`);
    if (!selected) return null;
  }
  await page.locator('input[name="name"]').first().fill(fixture.name);
  await page.locator('input[name="comment"]').first().fill(config.ownershipMarker);
  await page.locator('input[name="credentialLogin"]').first().fill(config.credentialLogin);
  if (fixture.kind === 'up') {
    await page.locator('input[name="password"]').first().fill(credentialPassword);
  }
  if (fixture.kind === 'usk') {
    const privateKey = page.locator('input[name="privateKey"]').first();
    const acceptsKey = await privateKey.count() && await privateKey.isEnabled().catch(() => false);
    if (acceptsKey) await privateKey.setInputFiles(config.sshPrivateKeyPath);
    add(acceptsKey ? 'pass' : 'fail', 'credential-smoke.usk.private-key', acceptsKey ? 'Attached an ephemeral SSH private key.' : 'Could not attach the ephemeral SSH private key.');
    if (!acceptsKey) return null;
  }
  await screenshot(page, `credential-dialog-filled-${fixture.kind}-${config.urlIndex}`);
  const listResponse = page.waitForResponse(isCredentialListResponse, {
    timeout: config.timeoutMs,
  }).catch(() => null);
  const saved = await clickFirst(page, [
    page.getByRole('button', {name: /^Save$/i}).first(),
    page.locator('button').filter({hasText: /^Save$/i}).first(),
  ]);
  if (!saved) {
    add('fail', `credential-smoke.${fixture.kind}.save`, 'Could not find the credential Save action.');
    return null;
  }
  await page.waitForLoadState('networkidle', {timeout: Math.min(config.timeoutMs, 5000)}).catch(() => null);
  await (await credentialRow(page, fixture.name)).waitFor({state: 'visible', timeout: config.timeoutMs}).catch(() => null);
  await screenshot(page, `credentials-after-create-${fixture.kind}-${config.urlIndex}`);
  const noNameError = await assertNoCredentialNameError(page, `credential-smoke.${fixture.kind}.create-name-validation`);
  const created = noNameError && await credentialRowVisible(page, fixture.name);
  const id = created ? await credentialIdFromResponse(await listResponse, fixture.name) : null;
  const identified = created && Boolean(id);
  add(identified ? 'pass' : 'fail', `credential-smoke.${fixture.kind}.created-visible`, identified ? 'Temporary credential is visible after save and has a stable identity.' : 'Temporary credential is not visible after save or lacks a stable identity.', {credentialName: fixture.name, credentialId: id});
  if (!identified) return null;
  const owned = {
    kind: fixture.kind,
    name: fixture.name,
    id,
    baseUrl: safeStoredUrl(config.baseUrl),
    ownershipMarker: config.ownershipMarker,
  };
  recordOwnedFixture(owned);
  return owned;
}

function hasExpectedSignature(format, bytes) {
  if (format === 'key') {
    const prefix = bytes.subarray(0, Math.min(bytes.length, 96)).toString('utf8').trimStart();
    return prefix.startsWith('ssh-') || prefix.startsWith('-----BEGIN');
  }
  return false;
}

async function removedDownloadActionsAreAbsent(page, fixtures) {
  await gotoStable(page, '/credentials');
  const unexpected = [];
  for (const fixture of fixtures) {
    const row = await credentialRow(page, fixture.name);
    for (const title of REMOVED_DOWNLOAD_TITLES) {
      if (await row.getByTitle(title).count()) {
        unexpected.push({credentialName: fixture.name, title});
      }
    }
  }
  const ok = unexpected.length === 0;
  add(ok ? 'pass' : 'fail', 'credential-smoke.download.removed-actions',
      ok ? 'Removed EXE/RPM/DEB credential download actions are absent.'
         : 'A removed credential download action is still advertised.',
      {unexpected});
  return ok;
}

async function characterizeDownload(page, fixture, format) {
  await gotoStable(page, '/credentials');
  const row = await credentialRow(page, fixture.name);
  const contract = DOWNLOAD_CONTRACTS[format];
  const action = row.getByTitle(contract.title).first();
  if (!(await action.count())) {
    add('fail', `credential-smoke.download.${format}.action`, `Could not find ${contract.title}.`);
    return {ok: false};
  }
  const captured = await captureDownloadRequest(page, action, format);
  const streamed = await boundedAuthenticatedGet(captured.url, captured.headers);
  const {bytes, declaredLength, headers} = streamed;
  const contentType = (headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  const contentEncoding = (headers['content-encoding'] || 'identity').trim().toLowerCase();
  const disposition = headers['content-disposition'] || '';
  const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
  const filename = filenameMatch ? path.basename(filenameMatch[1]) : '';
  const expectedFilename = `credential-${config.credentialLogin}.${contract.extension}`;
  const statusOk = streamed.status === 200;
  const contentTypeOk = contentType === contract.contentType;
  const filenameOk = filename === expectedFilename;
  const lengthMatched = bytes.length === declaredLength;
  const sizeOk = bytes.length === 80;
  const signatureOk = hasExpectedSignature(format, bytes);
  const operationalOk = statusOk && contentTypeOk && contentEncoding === 'identity' && filenameOk && lengthMatched && sizeOk && signatureOk;
  const ok = operationalOk;
  const message = ok
    ? `Characterized ${format.toUpperCase()} credential download transport.`
    : `${format.toUpperCase()} credential download violated the inherited transport contract.`;
  add(ok ? 'pass' : 'fail', `credential-smoke.download.${format}.contract`, message, {
    status: streamed.status,
    contentType,
    contentEncoding,
    filename,
    declaredLength,
    byteLength: bytes.length,
    signatureMatched: signatureOk,
  });
  return {
    ok,
    requestUrl: captured.url,
    requestHeaders: captured.headers,
  };
}

async function characterizeMissingCredential(requestUrl, requestHeaders) {
  const url = new URL(requestUrl);
  url.searchParams.set('credential_id', '00000000-0000-0000-0000-000000000000');
  const streamed = await boundedAuthenticatedGet(url.toString(), requestHeaders);
  const {bytes, declaredLength, headers} = streamed;
  const contentType = (headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  const contentEncoding = (headers['content-encoding'] || 'identity').trim().toLowerCase();
  const containsSecret = [loginPassword, credentialPassword]
    .filter(Boolean)
    .some(secret => bytes.includes(Buffer.from(secret, 'utf8')));
  const ok = streamed.status === 500
    && contentType === 'application/xml'
    && contentEncoding === 'identity'
    && bytes.length === declaredLength
    && bytes.length === 431
    && !containsSecret;
  add(ok ? 'pass' : 'fail', 'credential-smoke.download.missing.contract', ok ? 'Missing credential download retained its bounded failure contract without exposing configured secrets.' : 'Missing credential download did not match the bounded failure contract.', {
    status: streamed.status,
    contentType,
    contentEncoding,
    declaredLength,
    byteLength: bytes.length,
    containsConfiguredSecret: containsSecret,
  });
  return ok;
}

async function purgeCredentialFromTrash(page, fixture) {
  await gotoStable(page, '/trashcan#credential');
  const before = await fetchNativeTrashCredential(page, fixture.id);
  if (!before.ok) {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-purge-inventory`, 'Native trash inventory could not be verified before permanent credential cleanup.', {credentialName: fixture.name, credentialId: fixture.id, status: before.status});
    return false;
  }
  let decision = credentialCleanupDecision(fixture, before.items);
  if (decision.action === 'verify-live') {
    const live = await fetchNativeLiveCredential(page, fixture.id);
    decision = credentialCleanupDecision(fixture, before.items, live);
  }
  if (decision.action === 'live-unverified') {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-live-inventory`, 'The exact owned credential UUID was absent from Trashcan but its live state could not be verified.', {credentialName: fixture.name, credentialId: fixture.id});
    return false;
  }
  if (decision.action === 'live-present') {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-live-present`, 'Refusing to discard ownership because the exact credential UUID is still present in the live inventory.', {credentialName: fixture.name, credentialId: fixture.id});
    return false;
  }
  if (decision.action === 'absent') {
    forgetOwnedFixture(fixture);
    add('warn', `credential-smoke.${fixture.kind}.cleanup-purge`, 'Owned temporary credential was already absent from both the live and trash inventories.');
    return true;
  }
  if (decision.action !== 'purge') {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-purge-identity`, 'Refusing to purge a credential because the exact native Trashcan query does not map one matching UUID and name to the owned fixture.', {credentialName: fixture.name, expectedCredentialId: fixture.id, returnedItems: before.items.map(item => item && typeof item === 'object' ? {id: item.id, name: item.name, entityType: item.entity_type} : null)});
    return false;
  }

  const deletion = await deleteNativeTrashCredential(page, fixture.id);
  if (!deletion.ok) {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-purge-request`, 'Native permanent deletion of the exact owned credential UUID failed.', {credentialName: fixture.name, credentialId: fixture.id, status: deletion.status});
    return false;
  }

  const after = await fetchNativeTrashCredential(page, fixture.id);
  await page.reload({waitUntil: 'domcontentloaded', timeout: config.timeoutMs}).catch(() => null);
  await screenshot(page, `credentials-after-purge-${fixture.kind}-${config.urlIndex}`);
  const removed = after.ok && after.items.length === 0;
  if (removed) forgetOwnedFixture(fixture);
  add(removed ? 'pass' : 'fail', `credential-smoke.${fixture.kind}.cleanup-purge`, removed ? 'The exact owned credential UUID was permanently deleted through the native trash API.' : 'The exact owned credential UUID could not be proven absent from the native trash inventory after permanent cleanup.', {credentialName: fixture.name, credentialId: fixture.id, deleteStatus: deletion.status, inventoryStatus: after.status});
  return removed;
}

async function deleteCredential(page, fixture) {
  const live = await fetchNativeLiveCredential(page, fixture.id);
  if (!live.ok) {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-live-inventory`, 'The exact owned credential UUID could not be verified before cleanup.', {credentialName: fixture.name, credentialId: fixture.id, status: live.status});
    return false;
  }
  if (live.item === null) {
    return await purgeCredentialFromTrash(page, fixture);
  }
  if (live.item.id !== fixture.id || live.item.name !== fixture.name) {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-identity`, 'Refusing to delete a credential because the exact live UUID does not map to the owned fixture name.', {credentialName: fixture.name, expectedCredentialId: fixture.id, liveCredentialId: live.item.id, liveCredentialName: live.item.name});
    return false;
  }
  if (live.item.comment !== fixture.ownershipMarker) {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-authority`, 'Refusing to delete a credential because its server-side ownership marker does not match the retained fixture authority.', {credentialName: fixture.name, credentialId: fixture.id});
    return false;
  }
  const deletion = await deleteNativeLiveCredential(page, fixture.id);
  if (!deletion.ok) {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-request`, 'Native Trashcan move for the exact owned credential UUID failed.', {credentialName: fixture.name, credentialId: fixture.id, status: deletion.status});
    return false;
  }
  await gotoStable(page, '/credentials');
  await screenshot(page, `credentials-after-cleanup-${fixture.kind}-${config.urlIndex}`);
  const after = await fetchNativeLiveCredential(page, fixture.id);
  const removed = after.ok && after.item === null;
  add(removed ? 'pass' : 'fail', `credential-smoke.${fixture.kind}.cleanup`, removed ? 'The exact owned credential UUID was moved to Trashcan through the native API.' : 'The exact owned credential UUID could not be proven absent from the live inventory after cleanup.', {credentialName: fixture.name, credentialId: fixture.id, deleteStatus: deletion.status, inventoryStatus: after.status});
  return removed && await purgeCredentialFromTrash(page, fixture);
}

async function runForBaseUrl(baseUrl, urlIndex) {
  config.baseUrl = baseUrl;
  config.urlIndex = urlIndex;
  const browser = await chromium.launch({headless: true});
  const context = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1440, height: 1000}});
  const page = await context.newPage();
  page.setDefaultTimeout(config.timeoutMs);
  try {
    await login(page);
    if (config.cleanupOnly) {
      let cleaned = true;
      const applicableFixtures = fixturesForBaseUrl(
        ownedFixtures,
        baseUrl,
      );
      for (const fixture of [...applicableFixtures].reverse()) {
        cleaned = await deleteCredential(page, fixture) && cleaned;
      }
      add(cleaned ? 'pass' : 'fail', 'credential-smoke.timeout-cleanup', cleaned ? 'Owned timeout fixtures were cleaned.' : 'One or more owned timeout fixtures could not be cleaned.', {baseUrl: safeStoredUrl(baseUrl)});
      return;
    }
    const pendingRecovery = fixturesForBaseUrl(
      recoveryFixtures,
      baseUrl,
    );
    let recovered = true;
    for (const fixture of [...pendingRecovery].reverse()) {
      recovered = await deleteCredential(page, fixture) && recovered;
    }
    if (pendingRecovery.length > 0) {
      add(recovered ? 'pass' : 'fail', 'credential-smoke.retry-cleanup', recovered ? 'Recovered and cleaned all exact owned fixtures retained from a prior invocation.' : 'One or more exact owned fixtures from a prior invocation remain unresolved.', {baseUrl: safeStoredUrl(baseUrl), fixtureCount: pendingRecovery.length});
    }
    if (!recovered) return;
    let upFixture = null;
    let sshFixture = null;
    let downloadsOk = false;
    let missingOk = false;
    let requestUrl;
    let requestHeaders;
    let upCleaned = false;
    let sshCleaned = false;
    try {
      upFixture = await createCredential(page, {
        kind: 'up',
        name: config.credentialName,
      });
      sshFixture = await createCredential(page, {
        kind: 'usk',
        name: config.sshCredentialName,
        typeLabel: 'Username + SSH Key',
      });
      if (upFixture && sshFixture) {
        const removedActionsOk = await removedDownloadActionsAreAbsent(
          page,
          [upFixture, sshFixture],
        );
        const key = await characterizeDownload(page, sshFixture, 'key');
        requestUrl = key.requestUrl;
        requestHeaders = key.requestHeaders;
        downloadsOk = removedActionsOk && key.ok;
      }
    } finally {
      sshCleaned = sshFixture ? await deleteCredential(page, sshFixture) : true;
      upCleaned = upFixture ? await deleteCredential(page, upFixture) : true;
    }
    if (requestUrl && requestHeaders) {
      missingOk = await characterizeMissingCredential(requestUrl, requestHeaders);
    }
    const workflowOk = Boolean(upFixture) && Boolean(sshFixture) && downloadsOk && missingOk && upCleaned && sshCleaned;
    add(workflowOk ? 'pass' : 'fail', 'credential-smoke.workflow', workflowOk ? 'Credential lifecycle and download characterization completed.' : 'Credential lifecycle or download characterization failed.', {baseUrl: safeStoredUrl(baseUrl)});
  } finally {
    await context.close();
    await browser.close();
  }
}

(async () => {
  for (const [index, baseUrl] of config.baseUrls.entries()) {
    try {
      await runForBaseUrl(baseUrl, index);
    } catch (error) {
      add('fail', 'credential-smoke.exception', safeError(error), {baseUrl: safeStoredUrl(baseUrl)});
    }
  }
  const rank = {pass: 0, warn: 1, fail: 2};
  const status = findings.reduce((current, item) => rank[item.status] > rank[current] ? item.status : current, 'pass');
  const payload = {
    status,
    summary: status === 'pass' ? 'Runtime credential browser smoke passed.' : 'Runtime credential browser smoke found issues.',
    generated_at: new Date().toISOString(),
    findings,
    artifacts,
    metadata: {base_urls: config.baseUrls.map(safeStoredUrl), credential_name: config.credentialName, ssh_credential_name: config.sshCredentialName},
  };
  const output = artifactPath('credential-smoke.json');
  fs.writeFileSync(output, JSON.stringify(payload, null, 2) + '\n');
  payload.artifacts.push(output);
  console.log(JSON.stringify(payload));
})().catch(error => {
  const payload = {
    status: 'fail',
    summary: 'Runtime credential browser smoke crashed.',
    generated_at: new Date().toISOString(),
    findings: [{status: 'fail', check: 'credential-smoke.crash', message: safeError(error)}],
    artifacts,
    metadata: {base_urls: config.baseUrls.map(safeStoredUrl), credential_name: config.credentialName, ssh_credential_name: config.sshCredentialName},
  };
  console.log(JSON.stringify(payload));
  process.exit(1);
});
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def write_artifact(artifact_dir: Path, name: str, payload: dict[str, Any]) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def payload(status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "summary": summary, "generated_at": now_iso(), "details": details}


def redact_text(value: str, secrets: list[str]) -> str:
    redacted = value
    for secret in sorted((secret for secret in secrets if secret), key=len, reverse=True):
        redacted = redacted.replace(secret, "[redacted]")
    return redacted


def redact_value(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, list):
        return [redact_value(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item, secrets) for key, item in value.items()}
    return value


def sanitized_base_url(value: str) -> str:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("base URL must not contain user information")
    if parsed.path not in {"", "/"}:
        raise ValueError("base URL path must be /")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("base URL port is invalid") from error
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    hostname = parsed.hostname.lower()
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((scheme, netloc, "/", "", ""))


def json_object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError(f"JSON object contains duplicate key {key!r}")
        parsed[key] = value
    return parsed


FIXTURE_NAME_PATTERN = re.compile(
    r"^yafvs-credential-smoke-[0-9a-f]{8}(?:-ssh)?$"
)
OWNERSHIP_MARKER_PATTERN = re.compile(
    r"^yafvs-smoke:[A-Za-z0-9_-]{43}$"
)


def load_owned_fixtures(
    artifact_dir: Path, configured_base_urls: set[str]
) -> list[dict[str, str]]:
    state_path = artifact_dir / "credential-smoke-state.json"
    try:
        payload = json.loads(
            state_path.read_text(encoding="utf-8"),
            object_pairs_hook=json_object_without_duplicate_keys,
        )
    except FileNotFoundError:
        return []
    except (json.JSONDecodeError, OSError) as error:
        raise ValueError(
            "credential smoke state is unreadable or malformed"
        ) from error
    if not isinstance(payload, dict) or set(payload) != {"fixtures"}:
        raise ValueError("credential smoke state has a noncanonical root object")
    fixtures = payload.get("fixtures")
    if not isinstance(fixtures, list):
        raise ValueError("credential smoke state has no fixture list")
    retained: list[dict[str, str]] = []
    retained_identities: set[tuple[str, str]] = set()
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            raise ValueError("credential smoke state contains a malformed fixture")
        if set(fixture) != {
            "baseUrl",
            "id",
            "kind",
            "name",
            "ownershipMarker",
        }:
            raise ValueError(
                "credential smoke state contains a noncanonical fixture object"
            )
        kind = fixture.get("kind")
        name = fixture.get("name")
        credential_id = fixture.get("id")
        ownership_marker = fixture.get("ownershipMarker")
        if (
            kind not in {"up", "usk"}
            or not isinstance(name, str)
            or FIXTURE_NAME_PATTERN.fullmatch(name) is None
            or not isinstance(credential_id, str)
            or not isinstance(ownership_marker, str)
            or OWNERSHIP_MARKER_PATTERN.fullmatch(ownership_marker) is None
        ):
            raise ValueError("credential smoke state contains invalid fixture authority")
        if (kind == "usk") != name.endswith("-ssh"):
            raise ValueError("credential smoke fixture kind and name disagree")
        try:
            canonical_id = str(uuid.UUID(credential_id))
        except ValueError as error:
            raise ValueError("credential smoke fixture ID is invalid") from error
        if canonical_id != credential_id:
            raise ValueError("credential smoke fixture ID is not canonical")
        retained_fixture = {
            "kind": kind,
            "name": name,
            "id": canonical_id,
            "ownershipMarker": ownership_marker,
        }
        base_url = fixture.get("baseUrl")
        if not isinstance(base_url, str):
            raise ValueError("credential smoke fixture has no scoped base URL")
        try:
            canonical_base_url = sanitized_base_url(base_url)
        except ValueError as error:
            raise ValueError("credential smoke fixture base URL is invalid") from error
        if canonical_base_url != base_url:
            raise ValueError("credential smoke fixture base URL is not canonical")
        if canonical_base_url not in configured_base_urls:
            raise ValueError("credential smoke fixture belongs to an unconfigured base URL")
        identity = (canonical_base_url, canonical_id)
        if identity in retained_identities:
            raise ValueError("credential smoke state contains a duplicate fixture identity")
        retained_identities.add(identity)
        retained_fixture["baseUrl"] = canonical_base_url
        retained.append(retained_fixture)
    return retained


def run_node_process(
    command: list[str], *, env: dict[str, str], timeout: int
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        captured = error.output or ""
        if isinstance(captured, bytes):
            captured = captured.decode("utf-8", errors="replace")
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            tail, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            tail, _ = process.communicate()
        raise subprocess.TimeoutExpired(
            command,
            timeout,
            output=captured + (tail or ""),
        ) from error
    return subprocess.CompletedProcess(
        command,
        process.returncode,
        stdout=stdout,
    )


def timeout_cleanup(
    *,
    script_path: Path,
    config_path: Path,
    artifact_dir: Path,
    env: dict[str, str],
    redactions: list[str],
) -> dict[str, Any]:
    try:
        config = json.loads(
            config_path.read_text(encoding="utf-8"),
            object_pairs_hook=json_object_without_duplicate_keys,
        )
        configured_urls = config.get("baseUrls")
        if not isinstance(configured_urls, list) or not all(
            isinstance(url, str) for url in configured_urls
        ):
            raise ValueError("credential smoke cleanup config has no base URL list")
        canonical_urls = {sanitized_base_url(url) for url in configured_urls}
        if len(canonical_urls) != len(configured_urls) or any(
            sanitized_base_url(url) != url for url in configured_urls
        ):
            raise ValueError(
                "credential smoke cleanup config contains noncanonical base URLs"
            )
        fixtures = load_owned_fixtures(artifact_dir, canonical_urls)
    except (json.JSONDecodeError, OSError, ValueError) as error:
        return {
            "status": "fail",
            "summary": (
                "Credential timeout cleanup refused untrusted retained state: "
                f"{error}"
            ),
        }
    if not fixtures:
        return {
            "status": "pass",
            "summary": "No owned credential fixtures remained after timeout.",
        }
    config["cleanupOnly"] = True
    config["cleanupFixtures"] = fixtures
    cleanup_config_path = artifact_dir / "credential-smoke-cleanup-config.json"
    cleanup_config_path.write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    cleanup_config_path.chmod(0o600)
    try:
        completed = run_node_process(
            ["node", str(script_path), str(cleanup_config_path)],
            env=env,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "fail",
            "summary": "Owned timeout fixtures could not be cleaned within 60 seconds.",
            "artifact": str(cleanup_config_path),
        }
    try:
        cleanup_result = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        cleanup_result = {
            "status": "fail",
            "summary": "Timeout cleanup did not return parseable JSON.",
        }
    cleanup_result = redact_value(cleanup_result, redactions)
    return {
        "status": (
            "pass"
            if completed.returncode == 0
            and cleanup_result.get("status") in {"pass", "warn"}
            else "fail"
        ),
        "summary": cleanup_result.get(
            "summary", "Timeout cleanup completed without a summary."
        ),
        "artifact": str(cleanup_config_path),
    }


def run_credential_smoke(args: argparse.Namespace) -> dict[str, Any]:
    artifact_dir = Path(args.artifact_dir).expanduser().resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    base_urls = [sanitized_base_url(url) for url in args.base_url]
    login_password = Path(args.password_file).read_text(encoding="utf-8").strip()
    credential_password = os.environ.get("YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD")
    if not credential_password:
        failed = payload("fail", "Credential password material is missing.")
        failed["findings"] = [{"status": "fail", "check": "credential-smoke.credential-password", "message": "Set YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD."}]
        failed["artifacts"] = [write_artifact(artifact_dir, "credential-smoke-failed.json", failed)]
        return failed
    node_paths = playwright_node_path_candidates()
    if not node_paths:
        failed = payload("fail", "Playwright module was not found.", searched=list(node_paths))
        failed["findings"] = [{"status": "fail", "check": "playwright.module", "message": "No Playwright node_modules path was found."}]
        failed["artifacts"] = [write_artifact(artifact_dir, "credential-smoke-failed.json", failed)]
        return failed
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh_keygen:
        failed = payload("fail", "ssh-keygen was not found.")
        failed["findings"] = [{"status": "fail", "check": "credential-smoke.ssh-keygen", "message": "ssh-keygen is required to create an ephemeral SSH fixture."}]
        failed["artifacts"] = [write_artifact(artifact_dir, "credential-smoke-failed.json", failed)]
        return failed

    script_path = artifact_dir / "credential-smoke.cjs"
    config_path = artifact_dir / "credential-smoke-config.json"
    try:
        cleanup_fixtures = load_owned_fixtures(artifact_dir, set(base_urls))
    except ValueError as error:
        failed = payload(
            "fail",
            "Credential smoke state could not be trusted for destructive recovery.",
        )
        failed["findings"] = [
            {
                "status": "fail",
                "check": "credential-smoke.recovery-authority",
                "message": str(error),
            }
        ]
        failed["artifacts"] = [str(artifact_dir / "credential-smoke-state.json")]
        return failed
    ownership_marker = f"yafvs-smoke:{secrets.token_urlsafe(32)}"
    script_path.write_text(BROWSER_SCRIPT, encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="yafvs-credential-smoke-") as key_dir:
        private_key_path = Path(key_dir) / "id_ed25519"
        try:
            keygen = subprocess.run(
                [
                    ssh_keygen,
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "",
                    "-f",
                    str(private_key_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            failed = payload("fail", "Ephemeral SSH key generation timed out.")
            failed["findings"] = [{"status": "fail", "check": "credential-smoke.ssh-keygen-timeout", "message": "ssh-keygen exceeded its bounded runtime."}]
            failed["artifacts"] = [write_artifact(artifact_dir, "credential-smoke-failed.json", failed)]
            return failed
        if keygen.returncode != 0:
            failed = payload(
                "fail",
                "Ephemeral SSH key generation failed.",
                output_tail=redact_text(
                    keygen.stdout, [login_password, credential_password]
                ).splitlines()[-20:],
            )
            failed["findings"] = [{"status": "fail", "check": "credential-smoke.ssh-keygen", "message": "ssh-keygen could not create the ephemeral SSH fixture."}]
            failed["artifacts"] = [write_artifact(artifact_dir, "credential-smoke-failed.json", failed)]
            return failed
        config_path.write_text(
            json.dumps(
                {
                    "artifactDir": str(artifact_dir),
                    "baseUrls": base_urls,
                    "cleanupFixtures": cleanup_fixtures,
                    "credentialLogin": args.credential_login,
                    "credentialName": args.credential_name,
                    "sshCredentialName": f"{args.credential_name}-ssh",
                    "sshPrivateKeyPath": str(private_key_path),
                    "timeoutMs": args.timeout_ms,
                    "username": args.username,
                    "ownershipMarker": ownership_marker,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        config_path.chmod(0o600)

        env = dict(os.environ)
        env["NODE_PATH"] = os.pathsep.join([*node_paths, env.get("NODE_PATH", "")]).rstrip(os.pathsep)
        env["YAFVS_CREDENTIAL_SMOKE_LOGIN_PASSWORD"] = login_password
        env["YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD"] = credential_password
        try:
            completed = run_node_process(
                ["node", str(script_path), str(config_path)],
                env=env,
                timeout=max(
                    120,
                    min(
                        200,
                        (args.timeout_ms // 1000) * max(1, len(args.base_url)) * 8,
                    ),
                ),
            )
        except subprocess.TimeoutExpired as error:
            output = error.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            cleanup = timeout_cleanup(
                script_path=script_path,
                config_path=config_path,
                artifact_dir=artifact_dir,
                env=env,
                redactions=[login_password, credential_password],
            )
            result = payload(
                "fail",
                "Runtime credential browser smoke timed out.",
                output_tail=redact_text(
                    output, [login_password, credential_password]
                ).splitlines()[-80:],
                cleanup=cleanup,
            )
            result["findings"] = [{"status": "fail", "check": "credential-smoke.timeout", "message": "Credential browser smoke exceeded its bounded runtime."}]
            result["artifacts"] = [str(script_path), str(config_path)]
            if cleanup.get("artifact"):
                result["artifacts"].append(cleanup["artifact"])
            wrapper_artifact = write_artifact(
                artifact_dir, "credential-smoke-wrapper.json", result
            )
            result["artifacts"].append(wrapper_artifact)
            return result
    try:
        result = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        result = payload(
            "fail",
            "Runtime credential browser smoke did not return JSON.",
            exit_code=completed.returncode,
            output_tail=redact_text(
                completed.stdout, [login_password, credential_password]
            ).splitlines()[-80:],
        )
        result["findings"] = [{"status": "fail", "check": "credential-smoke.output", "message": "Credential smoke did not return parseable JSON."}]
        result["artifacts"] = []
    result = redact_value(result, [login_password, credential_password])
    result.setdefault("artifacts", [])
    result["artifacts"].extend([str(script_path), str(config_path)])
    result["status"] = result.get("status") if completed.returncode == 0 else "fail"
    wrapper_artifact = write_artifact(artifact_dir, "credential-smoke-wrapper.json", result)
    if wrapper_artifact not in result["artifacts"]:
        result["artifacts"].append(wrapper_artifact)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", action="append", required=True, help="GSA base URL to test; may be repeated")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--credential-name", required=True)
    parser.add_argument("--credential-login", default="yafvs-smoke")
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_credential_smoke(args)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") in {"pass", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Browser-level credential lifecycle and download smoke for the YAFVS runtime."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime_browser_smoke import DEFAULT_TIMEOUT_MS, playwright_node_path_candidates


BROWSER_SCRIPT = r"""
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const loginPassword = process.env.YAFVS_CREDENTIAL_SMOKE_LOGIN_PASSWORD || '';
const credentialPassword = process.env.YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD || '';
const findings = [];
const artifacts = [];
const MAX_DECLARED_DOWNLOAD_BYTES = 64 * 1024 * 1024;
const MAX_DECODED_DOWNLOAD_BYTES = 64 * 1024 * 1024;
const statePath = artifactPath('credential-smoke-state.json');
let ownedFixtures = Array.isArray(config.cleanupFixtures)
  ? config.cleanupFixtures.filter(fixture => fixture && fixture.name && fixture.kind)
  : [];
const DOWNLOAD_CONTRACTS = {
  exe: {
    title: 'Download Windows Executable (.exe)',
    contentType: 'application/exe',
    extension: 'exe',
    operational: false,
  },
  key: {
    title: 'Download Public Key',
    contentType: 'application/key',
    extension: 'pub',
    operational: true,
  },
  rpm: {
    title: 'Download RPM (.rpm) Package',
    contentType: 'application/rpm',
    extension: 'rpm',
    operational: false,
  },
  deb: {
    title: 'Download Debian (.deb) Package',
    contentType: 'application/deb',
    extension: 'deb',
    operational: false,
  },
};

function add(status, check, message, details = {}) {
  findings.push({status, check, message, details});
}

function safeError(error) {
  return String(error && error.stack ? error.stack : error)
    .replace(/([?&](?:token|access_token)=)[^&\s)]+/gi, '$1[redacted]');
}

function artifactPath(name) {
  return path.join(config.artifactDir, name);
}

function persistOwnedFixtures() {
  fs.writeFileSync(statePath, JSON.stringify({fixtures: ownedFixtures}, null, 2) + '\n');
  if (!artifacts.includes(statePath)) artifacts.push(statePath);
}

function recordOwnedFixture(fixture) {
  ownedFixtures = ownedFixtures.filter(existing => existing.name !== fixture.name);
  ownedFixtures.push(fixture);
  persistOwnedFixtures();
}

function forgetOwnedFixture(fixture) {
  ownedFixtures = ownedFixtures.filter(existing =>
    fixture.id ? existing.id !== fixture.id : existing.name !== fixture.name);
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
  if (!raw || !/^\d+$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
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

async function loadCredentialId(page, credentialName) {
  const listResponse = page.waitForResponse(isCredentialListResponse, {
    timeout: config.timeoutMs,
  }).catch(() => null);
  await gotoStable(page, '/credentials');
  return await credentialIdFromResponse(await listResponse, credentialName);
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
  add(loggedIn ? 'pass' : 'fail', 'credential-smoke.login', loggedIn ? 'Development operator login completed.' : 'Development operator login did not reach the application shell.', {url: page.url()});
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
  const owned = {kind: fixture.kind, name: fixture.name, id};
  recordOwnedFixture(owned);
  return owned;
}

function hasExpectedSignature(format, bytes) {
  if (format === 'exe') return bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a;
  if (format === 'rpm') return bytes.length >= 4 && bytes.subarray(0, 4).equals(Buffer.from([0xed, 0xab, 0xee, 0xdb]));
  if (format === 'deb') return bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from('!<arch>\n', 'ascii'));
  if (format === 'key') {
    const prefix = bytes.subarray(0, Math.min(bytes.length, 96)).toString('utf8').trimStart();
    return prefix.startsWith('ssh-') || prefix.startsWith('-----BEGIN');
  }
  return false;
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
  const [response] = await Promise.all([
    page.waitForResponse(candidate => {
      try {
        const url = new URL(candidate.url());
        return url.searchParams.get('cmd') === 'download_credential'
          && url.searchParams.get('package_format') === format;
      } catch {
        return false;
      }
    }, {timeout: config.timeoutMs}),
    action.click(),
  ]);
  const headers = response.headers();
  const declaredLength = declaredContentLength(headers);
  const contentType = (headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  const contentEncoding = (headers['content-encoding'] || 'identity').trim().toLowerCase();
  const disposition = headers['content-disposition'] || '';
  const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
  const filename = filenameMatch ? path.basename(filenameMatch[1]) : '';
  const expectedFilename = `credential-${config.credentialLogin}.${contract.extension}`;
  const statusOk = response.status() === 200;
  const contentTypeOk = contentType === contract.contentType;
  const filenameOk = filename === expectedFilename;
  const declaredBounded = declaredLength !== null
    && declaredLength <= MAX_DECLARED_DOWNLOAD_BYTES;
  if (!declaredBounded) {
    add('fail', `credential-smoke.download.${format}.declared-length`, 'Credential download omitted a safe Content-Length or exceeded the characterization cap.', {
      status: response.status(),
      contentType,
      filename,
      declaredLength,
    });
    return {ok: false};
  }
  const bytes = await response.body();
  const decodedBounded = bytes.length <= MAX_DECODED_DOWNLOAD_BYTES;
  const lengthMatched = contentEncoding !== 'identity'
    || bytes.length === declaredLength;
  const sizeOk = format === 'key'
    ? bytes.length === 80
    : bytes.length > 0;
  const signatureOk = hasExpectedSignature(format, bytes);
  const operationalOk = statusOk && contentTypeOk && filenameOk && decodedBounded && lengthMatched && sizeOk && signatureOk;
  const knownEmpty = statusOk && contentTypeOk && filenameOk && decodedBounded && lengthMatched && bytes.length === 0;
  const ok = contract.operational ? operationalOk : knownEmpty;
  const status = ok && !contract.operational ? 'warn' : ok ? 'pass' : 'fail';
  const message = contract.operational
    ? (ok ? `Characterized ${format.toUpperCase()} credential download transport.` : `${format.toUpperCase()} credential download violated the inherited transport contract.`)
    : (ok ? `${format.toUpperCase()} remains advertised but returns an empty body; this broken inherited surface should be removed.` : `${format.toUpperCase()} no longer matches the characterized empty inherited response.`);
  add(status, `credential-smoke.download.${format}.contract`, message, {
    status: response.status(),
    contentType,
    contentEncoding,
    filename,
    declaredLength,
    byteLength: bytes.length,
    signatureMatched: signatureOk,
    operational: contract.operational,
  });
  return {ok, requestUrl: response.url()};
}

async function characterizeMissingCredential(page, requestUrl) {
  const url = new URL(requestUrl);
  url.searchParams.set('credential_id', '00000000-0000-0000-0000-000000000000');
  const response = await page.context().request.get(url.toString());
  const contentType = (response.headers()['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  const contentEncoding = (response.headers()['content-encoding'] || 'identity').trim().toLowerCase();
  const declaredLength = declaredContentLength(response.headers());
  if (declaredLength === null || declaredLength > MAX_DECLARED_DOWNLOAD_BYTES) {
    add('fail', 'credential-smoke.download.missing.declared-length', 'Missing credential response omitted a safe Content-Length or exceeded the characterization cap.', {
      status: response.status(),
      contentType,
      declaredLength,
    });
    return false;
  }
  const bytes = await response.body();
  const containsSecret = [loginPassword, credentialPassword]
    .filter(Boolean)
    .some(secret => bytes.includes(Buffer.from(secret, 'utf8')));
  const ok = response.status() === 500
    && contentType === 'application/xml'
    && (contentEncoding !== 'identity' || bytes.length === declaredLength)
    && bytes.length === 431
    && !containsSecret;
  add(ok ? 'pass' : 'fail', 'credential-smoke.download.missing.contract', ok ? 'Missing credential download retained its bounded failure contract without exposing configured secrets.' : 'Missing credential download did not match the bounded failure contract.', {
    status: response.status(),
    contentType,
    contentEncoding,
    declaredLength,
    byteLength: bytes.length,
    containsConfiguredSecret: containsSecret,
  });
  return ok;
}

async function deleteCredential(page, fixture) {
  const listedId = await loadCredentialId(page, fixture.name);
  const row = await credentialRow(page, fixture.name);
  if (!(await row.count())) {
    forgetOwnedFixture(fixture);
    add('warn', `credential-smoke.${fixture.kind}.cleanup`, 'Owned temporary credential row was already absent during cleanup.');
    return true;
  }
  if (!listedId || listedId !== fixture.id) {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-identity`, 'Refusing to delete a credential because the visible name does not map to the owned fixture UUID.', {credentialName: fixture.name, expectedCredentialId: fixture.id, listedCredentialId: listedId});
    return false;
  }
  const deleteClicked = await clickFirst(page, [
    row.getByTitle('Move Credential to trashcan').first(),
    row.getByTitle(/trashcan/i).first(),
  ]);
  if (!deleteClicked) {
    add('fail', `credential-smoke.${fixture.kind}.cleanup-click`, 'Temporary credential row was visible but the trashcan action was not found.');
    await screenshot(page, `credential-cleanup-action-missing-${fixture.kind}-${config.urlIndex}`);
    return false;
  }
  await page.waitForLoadState('networkidle', {timeout: Math.min(config.timeoutMs, 5000)}).catch(() => null);
  await row.waitFor({state: 'detached', timeout: config.timeoutMs}).catch(() => null);
  await screenshot(page, `credentials-after-cleanup-${fixture.kind}-${config.urlIndex}`);
  const removed = !(await credentialRowVisible(page, fixture.name));
  if (removed) forgetOwnedFixture(fixture);
  add(removed ? 'pass' : 'fail', `credential-smoke.${fixture.kind}.cleanup`, removed ? 'Owned temporary credential was moved to trashcan.' : 'Owned temporary credential is still visible after cleanup.', {credentialName: fixture.name, credentialId: fixture.id});
  return removed;
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
      for (const fixture of [...ownedFixtures].reverse()) {
        cleaned = await deleteCredential(page, fixture) && cleaned;
      }
      add(cleaned ? 'pass' : 'fail', 'credential-smoke.timeout-cleanup', cleaned ? 'Owned timeout fixtures were cleaned.' : 'One or more owned timeout fixtures could not be cleaned.', {baseUrl});
      return;
    }
    let upFixture = null;
    let sshFixture = null;
    let downloadsOk = false;
    let missingOk = false;
    let requestUrl;
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
        const exe = await characterizeDownload(page, upFixture, 'exe');
        const key = await characterizeDownload(page, sshFixture, 'key');
        const rpm = await characterizeDownload(page, sshFixture, 'rpm');
        const deb = await characterizeDownload(page, sshFixture, 'deb');
        requestUrl = key.requestUrl;
        downloadsOk = [exe, key, rpm, deb].every(result => result.ok);
      }
    } finally {
      sshCleaned = sshFixture ? await deleteCredential(page, sshFixture) : true;
      upCleaned = upFixture ? await deleteCredential(page, upFixture) : true;
    }
    if (requestUrl) {
      missingOk = await characterizeMissingCredential(page, requestUrl);
    }
    const workflowOk = Boolean(upFixture) && Boolean(sshFixture) && downloadsOk && missingOk && upCleaned && sshCleaned;
    add(workflowOk ? 'pass' : 'fail', 'credential-smoke.workflow', workflowOk ? 'Credential lifecycle and download characterization completed.' : 'Credential lifecycle or download characterization failed.', {baseUrl});
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
      add('fail', 'credential-smoke.exception', safeError(error), {baseUrl});
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
    metadata: {base_urls: config.baseUrls, credential_name: config.credentialName, ssh_credential_name: config.sshCredentialName},
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
    metadata: {base_urls: config.baseUrls, credential_name: config.credentialName, ssh_credential_name: config.sshCredentialName},
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
    state_path = artifact_dir / "credential-smoke-state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {
            "status": "pass",
            "summary": "No owned credential fixtures were recorded before timeout.",
        }
    fixtures = state.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        return {
            "status": "pass",
            "summary": "No owned credential fixtures remained after timeout.",
        }
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["cleanupOnly"] = True
    config["cleanupFixtures"] = fixtures
    cleanup_config_path = artifact_dir / "credential-smoke-cleanup-config.json"
    cleanup_config_path.write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
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
                    "baseUrls": args.base_url,
                    "credentialLogin": args.credential_login,
                    "credentialName": args.credential_name,
                    "sshCredentialName": f"{args.credential_name}-ssh",
                    "sshPrivateKeyPath": str(private_key_path),
                    "timeoutMs": args.timeout_ms,
                    "username": args.username,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

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

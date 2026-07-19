#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Browser-level credential creation smoke for the YAFVS runtime."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
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

function add(status, check, message, details = {}) {
  findings.push({status, check, message, details});
}

function artifactPath(name) {
  return path.join(config.artifactDir, name);
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

async function credentialRow(page) {
  return page.locator('tbody tr').filter({hasText: config.credentialName}).first();
}

async function credentialRowVisible(page) {
  const row = await credentialRow(page);
  return await row.count() > 0 && await row.isVisible().catch(() => false);
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

async function createCredential(page) {
  await page.goto(new URL('/credentials', config.baseUrl).toString(), {waitUntil: 'networkidle', timeout: config.timeoutMs});
  await screenshot(page, `credentials-before-create-${config.urlIndex}`);
  const newClicked = await clickFirst(page, [
    page.getByTitle('New Credential').first(),
    page.getByRole('button', {name: /new credential/i}).first(),
  ]);
  add(newClicked ? 'pass' : 'fail', 'credential-smoke.new-button', newClicked ? 'Opened the New Credential dialog.' : 'Could not find the New Credential action.');
  if (!newClicked) return false;

  await page.locator('input[name="name"]').first().waitFor({state: 'visible', timeout: config.timeoutMs});
  await page.locator('input[name="name"]').first().fill(config.credentialName);
  await page.locator('input[name="credentialLogin"]').first().fill(config.credentialLogin);
  await page.locator('input[name="password"]').first().fill(credentialPassword);
  await screenshot(page, `credential-dialog-filled-${config.urlIndex}`);
  await clickFirst(page, [
    page.getByRole('button', {name: /^Save$/i}).first(),
    page.locator('button').filter({hasText: /^Save$/i}).first(),
  ]);
  await page.waitForLoadState('networkidle', {timeout: config.timeoutMs}).catch(() => null);
  await page.waitForFunction(name => Array.from(document.querySelectorAll('tbody tr')).some(row => row.innerText.includes(name)), config.credentialName, {timeout: config.timeoutMs}).catch(() => null);
  await screenshot(page, `credentials-after-create-${config.urlIndex}`);
  const noNameError = await assertNoCredentialNameError(page, 'credential-smoke.create-name-validation');
  const created = await credentialRowVisible(page);
  add(created ? 'pass' : 'fail', 'credential-smoke.created-visible', created ? 'Temporary credential is visible after save.' : 'Temporary credential is not visible after save.', {credentialName: config.credentialName});
  return noNameError && created;
}

async function deleteCredential(page) {
  await page.goto(new URL('/credentials', config.baseUrl).toString(), {waitUntil: 'networkidle', timeout: config.timeoutMs});
  const row = await credentialRow(page);
  if (!(await row.count())) {
    add('warn', 'credential-smoke.cleanup', 'Temporary credential row was not visible during cleanup; it may not have been created.');
    return true;
  }
  const deleteClicked = await clickFirst(page, [
    row.getByTitle('Move Credential to trashcan').first(),
    row.getByTitle(/trashcan/i).first(),
  ]);
  if (!deleteClicked) {
    add('fail', 'credential-smoke.cleanup-click', 'Temporary credential row was visible but the trashcan action was not found.');
    await screenshot(page, `credential-cleanup-action-missing-${config.urlIndex}`);
    return false;
  }
  const confirmClicked = await clickFirst(page, [
    page.getByRole('button', {name: /Move to Trashcan/i}).first(),
    page.getByText('Move to Trashcan').first(),
    page.getByRole('button', {name: /Delete/i}).first(),
  ]);
  if (!confirmClicked) {
    add('fail', 'credential-smoke.cleanup-confirm', 'Trashcan confirmation did not expose a recognizable confirmation action.');
    await screenshot(page, `credential-cleanup-confirm-missing-${config.urlIndex}`);
    return false;
  }
  await page.waitForLoadState('networkidle', {timeout: config.timeoutMs}).catch(() => null);
  await page.waitForFunction(name => !Array.from(document.querySelectorAll('tbody tr')).some(row => row.innerText.includes(name)), config.credentialName, {timeout: config.timeoutMs}).catch(() => null);
  await screenshot(page, `credentials-after-cleanup-${config.urlIndex}`);
  const removed = !(await credentialRowVisible(page));
  add(removed ? 'pass' : 'fail', 'credential-smoke.cleanup', removed ? 'Temporary credential was moved to trashcan.' : 'Temporary credential is still visible after cleanup.', {credentialName: config.credentialName});
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
    const created = await createCredential(page);
    const cleaned = await deleteCredential(page);
    add(created && cleaned ? 'pass' : 'fail', 'credential-smoke.workflow', created && cleaned ? 'Credential create/cleanup workflow completed.' : 'Credential create/cleanup workflow failed.', {baseUrl});
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
      add('fail', 'credential-smoke.exception', String(error && error.stack ? error.stack : error), {baseUrl});
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
    metadata: {base_urls: config.baseUrls, credential_name: config.credentialName},
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
    findings: [{status: 'fail', check: 'credential-smoke.crash', message: String(error && error.stack ? error.stack : error)}],
    artifacts,
    metadata: {base_urls: config.baseUrls, credential_name: config.credentialName},
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


def run_credential_smoke(args: argparse.Namespace) -> dict[str, Any]:
    artifact_dir = Path(args.artifact_dir).expanduser().resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    login_password = Path(args.password_file).read_text(encoding="utf-8").strip()
    node_paths = playwright_node_path_candidates()
    if not node_paths:
        failed = payload("fail", "Playwright module was not found.", searched=list(node_paths))
        failed["findings"] = [{"status": "fail", "check": "playwright.module", "message": "No Playwright node_modules path was found."}]
        failed["artifacts"] = [write_artifact(artifact_dir, "credential-smoke-failed.json", failed)]
        return failed

    script_path = artifact_dir / "credential-smoke.cjs"
    config_path = artifact_dir / "credential-smoke-config.json"
    script_path.write_text(BROWSER_SCRIPT, encoding="utf-8")
    config_path.write_text(
        json.dumps(
            {
                "artifactDir": str(artifact_dir),
                "baseUrls": args.base_url,
                "credentialLogin": args.credential_login,
                "credentialName": args.credential_name,
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
    env["YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD"] = args.credential_password
    completed = subprocess.run(
        ["node", str(script_path), str(config_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        timeout=max(60, (args.timeout_ms // 1000) * max(1, len(args.base_url)) * 5),
    )
    try:
        result = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        result = payload(
            "fail",
            "Runtime credential browser smoke did not return JSON.",
            exit_code=completed.returncode,
            output_tail=completed.stdout.splitlines()[-80:],
        )
        result["findings"] = [{"status": "fail", "check": "credential-smoke.output", "message": "Credential smoke did not return parseable JSON."}]
        result["artifacts"] = []
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
    parser.add_argument("--credential-login", default="turbovas-smoke")
    parser.add_argument("--credential-password", required=True)
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_credential_smoke(args)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") in {"pass", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

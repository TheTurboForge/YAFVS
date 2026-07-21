// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

import {execFile} from 'node:child_process';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';

import {parseDocument} from 'yaml';

import {
  normalizeOperationRegistry,
  renderOperationRegistry,
} from './openapi-operation-registry.mjs';

const execFileAsync = promisify(execFile);
const scriptDirectory = fileURLToPath(new URL('.', import.meta.url));
const projectDirectory = resolve(scriptDirectory, '..');
const defaultContract = resolve(
  scriptDirectory,
  '../../../api/openapi/yafvs-v1.yaml',
);
const writeOperationRegistry = process.argv.includes(
  '--write-operation-registry',
);
const contractArgument = process.argv
  .slice(2)
  .find(argument => !argument.startsWith('--'));
const contractPath = resolve(contractArgument ?? defaultContract);
const operationRegistryPath = resolve(
  scriptDirectory,
  '../../../docs/NATIVE_API_OPERATION_REGISTRY.md',
);
const binary = name => resolve(projectDirectory, 'node_modules/.bin', name);

const decodeJsonPointerToken = token =>
  decodeURIComponent(token).replaceAll('~1', '/').replaceAll('~0', '~');

const resolveInternalReference = (root, reference) => {
  if (reference === '#') return root;
  if (!reference.startsWith('#/')) return undefined;

  return reference
    .slice(2)
    .split('/')
    .map(decodeJsonPointerToken)
    .reduce((value, token) => {
      if (
        value === null ||
        typeof value !== 'object' ||
        !Object.hasOwn(value, token)
      ) {
        throw new Error(`Unresolved internal OpenAPI reference: ${reference}`);
      }
      return value[token];
    }, root);
};

const verifyInternalReferences = root => {
  const pending = [root];
  const visited = new WeakSet();
  let count = 0;

  while (pending.length > 0) {
    const value = pending.pop();
    if (value === null || typeof value !== 'object' || visited.has(value)) {
      continue;
    }
    visited.add(value);

    if (typeof value.$ref === 'string' && value.$ref.startsWith('#')) {
      resolveInternalReference(root, value.$ref);
      count += 1;
    }
    pending.push(...Object.values(value));
  }

  return count;
};

const run = async (name, args) => {
  try {
    return await execFileAsync(binary(name), args, {
      cwd: projectDirectory,
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    const output = [error.stdout, error.stderr].filter(Boolean).join('\n');
    throw new Error(`${name} failed${output ? `:\n${output}` : ''}`, {
      cause: error,
    });
  }
};

let temporaryDirectory;
try {
  if (writeOperationRegistry && contractArgument !== undefined) {
    throw new Error(
      '--write-operation-registry may generate only from the canonical OpenAPI contract.',
    );
  }
  const source = await readFile(contractPath, 'utf8');
  const yamlDocument = parseDocument(source, {
    prettyErrors: true,
    uniqueKeys: true,
  });
  if (yamlDocument.errors.length > 0) {
    throw new Error(
      `OpenAPI YAML parsing failed:\n${yamlDocument.errors
        .map(error => error.message)
        .join('\n')}`,
    );
  }
  const contract = yamlDocument.toJS({maxAliasCount: 100});
  console.log('1/4 OpenAPI YAML and duplicate-key check passed.');

  await run('redocly', [
    'lint',
    contractPath,
    '--extends=spec',
    '--format=stylish',
  ]);
  console.log('2/4 OpenAPI 3.1 semantic validation passed.');

  const referenceCount = verifyInternalReferences(contract);
  const {rows: operationRows} = normalizeOperationRegistry(contract);
  console.log(
    `3/4 Resolved all ${referenceCount} internal OpenAPI references.`,
  );
  console.log(
    `Operation registry metadata is complete for ${operationRows.length} operations.`,
  );

  temporaryDirectory = await mkdtemp(join(projectDirectory, '.openapi-check-'));
  const generatedTypes = join(temporaryDirectory, 'schema.d.ts');
  const disposableClient = join(temporaryDirectory, 'client.ts');
  await run('openapi-typescript', [contractPath, '--output', generatedTypes]);
  await writeFile(
    disposableClient,
    `import createClient from 'openapi-fetch';\n` +
      `import type {paths} from './schema.js';\n\n` +
      `const client = createClient<paths>({baseUrl: 'http://127.0.0.1'});\n` +
      `void client.GET('/results');\n`,
  );
  await run('tsc', [
    '--noEmit',
    '--strict',
    '--target',
    'ES2022',
    '--module',
    'NodeNext',
    '--moduleResolution',
    'NodeNext',
    '--lib',
    'ES2022,DOM',
    '--skipLibCheck',
    disposableClient,
    generatedTypes,
  ]);
  console.log('4/4 Generated and compiled a disposable typed API client.');
  const renderedRegistry = renderOperationRegistry(contract);
  if (writeOperationRegistry) {
    await writeFile(operationRegistryPath, renderedRegistry);
    console.log(
      `Updated generated operation registry: ${operationRegistryPath}`,
    );
  } else {
    const trackedRegistry = await readFile(operationRegistryPath, 'utf8');
    if (trackedRegistry !== renderedRegistry) {
      throw new Error(
        'Generated operation registry is stale; run npm run generate:openapi-registry.',
      );
    }
    console.log('Generated operation registry documentation is synchronized.');
  }
  console.log(`OpenAPI contract gate passed: ${contractPath}`);
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
} finally {
  if (temporaryDirectory !== undefined) {
    await rm(temporaryDirectory, {force: true, recursive: true});
  }
}

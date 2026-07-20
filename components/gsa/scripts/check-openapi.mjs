// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {parseDocument} from 'yaml';

const scriptDirectory = fileURLToPath(new URL('.', import.meta.url));
const defaultContract = resolve(
  scriptDirectory,
  '../../../api/openapi/yafvs-v1.yaml',
);
const contractPath = resolve(process.argv[2] ?? defaultContract);
const source = await readFile(contractPath, 'utf8');
const document = parseDocument(source, {
  prettyErrors: true,
  uniqueKeys: true,
});

if (document.errors.length > 0) {
  for (const error of document.errors) {
    console.error(error.message);
  }
  process.exitCode = 1;
} else {
  document.toJS({maxAliasCount: 100});
  console.log(`OpenAPI YAML syntax is valid: ${contractPath}`);
}

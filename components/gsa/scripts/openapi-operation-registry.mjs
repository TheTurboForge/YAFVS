// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

const HTTP_METHODS = new Set([
  'delete',
  'get',
  'head',
  'options',
  'patch',
  'post',
  'put',
  'trace',
]);

const REQUIRED_PROFILE_FIELDS = [
  'exposure',
  'surfaces',
  'principals',
  'authentication',
  'team-authority',
  'write-gate',
  'schema-compatibility',
  'request-limits',
  'destructive-classification',
  'confirmation',
  'idempotency',
  'audit-event',
];
const PROFILE_TEXT_FIELDS = REQUIRED_PROFILE_FIELDS.filter(
  field => !['surfaces', 'principals', 'authentication'].includes(field),
);
const ALLOWED_SURFACES = new Set(['internal', 'browser-proxy', 'direct']);

const requireText = (value, field) => {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(
      'Operation registry field ' + field + ' must be non-empty text.',
    );
  }
  return value;
};

const operationClassification = (method, operation) => {
  if (method === 'get' || method === 'head' || method === 'options') {
    return 'read-only';
  }
  if (method === 'delete') return 'destructive';
  return operation['x-yafvs-side-effect'] === undefined
    ? 'mutating'
    : 'mutating-control';
};

const operationConfirmation = method => {
  if (['get', 'head', 'options'].includes(method)) return 'none';
  if (method === 'delete') return 'client-confirmation-required';
  return 'operation-specific';
};

const operationIdempotency = method => {
  if (['get', 'head', 'options', 'put', 'delete'].includes(method)) {
    return 'http-idempotent';
  }
  if (method === 'patch') return 'contract-specific';
  return 'not-assumed';
};

export const normalizeOperationRegistry = contract => {
  const profiles = contract['x-yafvs-operation-profiles'];
  if (
    profiles === null ||
    typeof profiles !== 'object' ||
    Array.isArray(profiles)
  ) {
    throw new Error('OpenAPI must define x-yafvs-operation-profiles.');
  }

  for (const [name, profile] of Object.entries(profiles)) {
    for (const field of REQUIRED_PROFILE_FIELDS) {
      if (!Object.hasOwn(profile, field)) {
        throw new Error(
          'Operation profile ' + name + ' is missing ' + field + '.',
        );
      }
    }
    for (const field of PROFILE_TEXT_FIELDS) {
      requireText(profile[field], name + ' ' + field);
    }
    if (
      !Array.isArray(profile.surfaces) ||
      profile.surfaces.length === 0 ||
      !profile.surfaces.every(surface => ALLOWED_SURFACES.has(surface)) ||
      new Set(profile.surfaces).size !== profile.surfaces.length
    ) {
      throw new Error('Operation profile ' + name + ' has invalid surfaces.');
    }
    if (
      !Array.isArray(profile.principals) ||
      profile.principals.length === 0 ||
      !profile.principals.every(
        principal => typeof principal === 'string' && principal.length > 0,
      ) ||
      new Set(profile.principals).size !== profile.principals.length
    ) {
      throw new Error('Operation profile ' + name + ' has invalid principals.');
    }
    if (
      profile.authentication === null ||
      typeof profile.authentication !== 'object' ||
      Array.isArray(profile.authentication)
    ) {
      throw new Error(
        'Operation profile ' + name + ' has invalid authentication.',
      );
    }
    const authenticationSurfaces = Object.keys(profile.authentication);
    if (
      authenticationSurfaces.length !== profile.surfaces.length ||
      authenticationSurfaces.some(
        surface => !profile.surfaces.includes(surface),
      )
    ) {
      throw new Error(
        'Operation profile ' + name + ' authentication surfaces do not match.',
      );
    }
    for (const surface of profile.surfaces) {
      if (!Object.hasOwn(profile.authentication, surface)) {
        throw new Error(
          'Operation profile ' +
            name +
            ' lacks authentication for ' +
            surface +
            '.',
        );
      }
      requireText(
        profile.authentication[surface],
        name + ' authentication.' + surface,
      );
    }
  }

  const rows = [];
  const operationIds = new Set();
  for (const [path, pathItem] of Object.entries(contract.paths ?? {})) {
    for (const [method, operation] of Object.entries(pathItem)) {
      if (!HTTP_METHODS.has(method)) continue;
      const operationId = requireText(
        operation.operationId,
        method + ' ' + path + ' operationId',
      );
      if (operationIds.has(operationId)) {
        throw new Error(
          'Duplicate operationId in operation registry: ' + operationId,
        );
      }
      operationIds.add(operationId);

      const profileName = requireText(
        operation['x-yafvs-profile'],
        method + ' ' + path + ' x-yafvs-profile',
      );
      const profile = profiles[profileName];
      if (profile === undefined) {
        throw new Error(
          method + ' ' + path + ' selects unknown profile ' + profileName + '.',
        );
      }
      if (operation['x-yafvs-exposure'] !== profile.exposure) {
        throw new Error(
          method +
            ' ' +
            path +
            ' exposure does not match operation profile ' +
            profileName +
            '.',
        );
      }
      const expectedDirect = profile.surfaces.includes('direct');
      if ((operation['x-yafvs-direct'] === true) !== expectedDirect) {
        throw new Error(
          method +
            ' ' +
            path +
            ' direct marker does not match operation profile.',
        );
      }
      if ((method === 'get') !== (profile.exposure === 'direct-read')) {
        throw new Error(
          method +
            ' ' +
            path +
            ' read/write profile conflicts with its method.',
        );
      }
      requireText(
        operation['x-yafvs-maturity'],
        method + ' ' + path + ' maturity',
      );
      requireText(
        operation['x-yafvs-replaces'],
        method + ' ' + path + ' migration owner',
      );

      rows.push({
        method: method.toUpperCase(),
        path,
        operationId,
        profileName,
        profile,
        maturity: operation['x-yafvs-maturity'],
        replaces: operation['x-yafvs-replaces'],
        residualOwner:
          operation['x-yafvs-inherited-still-owns'] ?? 'none-recorded',
        teamAuthority:
          operation['x-yafvs-team-authority'] ?? profile['team-authority'],
        classification: operationClassification(method, operation),
        confirmation: operationConfirmation(method),
        idempotency: operationIdempotency(method),
        auditEvent: profile['audit-event'],
      });
    }
  }
  rows.sort(
    (left, right) =>
      left.path.localeCompare(right.path) ||
      left.method.localeCompare(right.method),
  );
  if (rows.length === 0)
    throw new Error('Operation registry contains no operations.');
  return {profiles, rows};
};

const cell = value =>
  String(Array.isArray(value) ? value.join(', ') : value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('|', '&#124;')
    .replaceAll('\n', ' ');

const authenticationCell = authentication =>
  Object.entries(authentication)
    .map(([surface, mechanism]) => surface + ': ' + mechanism)
    .join('; ');

export const renderOperationRegistry = contract => {
  const {profiles, rows} = normalizeOperationRegistry(contract);
  const profileCounts = new Map();
  for (const row of rows) {
    profileCounts.set(
      row.profileName,
      (profileCounts.get(row.profileName) ?? 0) + 1,
    );
  }

  const lines = [
    '<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->',
    '<!-- SPDX-License-Identifier: GPL-3.0-or-later -->',
    '',
    '# Native API Operation Registry',
    '',
    'This document is generated from api/openapi/yafvs-v1.yaml. Edit the OpenAPI',
    'operation profiles and operation metadata, then run npm run',
    'generate:openapi-registry in components/gsa. The Quality Gate rejects drift.',
    '',
    'The registry describes current development exposure, not production readiness.',
    'The direct listener remains opt-in, bearer-authenticated, loopback by default,',
    'and subject to its positive route allowlist and explicit write-control gate.',
    '',
    '## Security Profiles',
    '',
    '| Profile | Operations | Surfaces | Principals | Authentication | Write gate | Schema compatibility | Request limits |',
    '| --- | ---: | --- | --- | --- | --- | --- | --- |',
  ];
  for (const [name, profile] of Object.entries(profiles)) {
    lines.push(
      '| ' +
        [
          name,
          profileCounts.get(name) ?? 0,
          cell(profile.surfaces),
          cell(profile.principals),
          cell(authenticationCell(profile.authentication)),
          cell(profile['write-gate']),
          cell(profile['schema-compatibility']),
          cell(profile['request-limits']),
        ].join(' | ') +
        ' |',
    );
  }

  lines.push(
    '',
    '## Generated Test Matrix',
    '',
    '| Profile | Exposure | Destructive classification | Confirmation | Idempotency | Audit event |',
    '| --- | --- | --- | --- | --- | --- |',
  );
  for (const [name, profile] of Object.entries(profiles)) {
    lines.push(
      '| ' +
        [
          name,
          profile.exposure,
          profile['destructive-classification'],
          profile.confirmation,
          profile.idempotency,
          profile['audit-event'],
        ]
          .map(cell)
          .join(' | ') +
        ' |',
    );
  }

  lines.push(
    '',
    '## Operations and Migration State',
    '',
    '| Method | Path | Profile | Maturity | Native replacement | Residual inherited owner | Team authority | Classification | Confirmation | Idempotency | Audit event |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
  );
  for (const row of rows) {
    lines.push(
      '| ' +
        [
          row.method,
          row.path,
          row.profileName,
          row.maturity,
          row.replaces,
          row.residualOwner,
          row.teamAuthority,
          row.classification,
          row.confirmation,
          row.idempotency,
          row.auditEvent,
        ]
          .map(cell)
          .join(' | ') +
        ' |',
    );
  }
  lines.push('');
  return lines.join('\n');
};

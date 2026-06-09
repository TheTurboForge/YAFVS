/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import Host from 'gmp/models/host';
import {parseModelFromElement} from 'gmp/models/model';
import Nvt from 'gmp/models/nvt';
import {
  getEntityType,
  pluralizeType,
  normalizeType,
  apiType,
  typeName,
  resourceType,
  type EntityType,
  entityURL,
} from 'gmp/utils/entity-type';

describe('getEntityType function tests', () => {
  test('should return entity type of object', () => {
    const model = {entityType: 'task' as const};

    expect(getEntityType(model)).toEqual('task');
  });

  test('should return entity type of model', () => {
    const model = parseModelFromElement({}, 'task');

    expect(getEntityType(model)).toEqual('task');
  });

  test('should return entity type for info models', () => {
    const model = Nvt.fromElement();

    expect(getEntityType(model)).toEqual('nvt');
  });

  test('should return entity type for asset models', () => {
    const model = Host.fromElement();

    expect(getEntityType(model)).toEqual('host');
  });
});

describe('pluralizeType function tests', () => {
  test('should not pluralize info', () => {
    expect(pluralizeType('info')).toEqual('info');
  });

  test('should not pluralize an already pluralized term', () => {
    expect(pluralizeType('foos')).toEqual('foos');
    expect(pluralizeType('tasks')).toEqual('tasks');
  });

  test('should pluralize term', () => {
    expect(pluralizeType('foo')).toEqual('foos');
    expect(pluralizeType('task')).toEqual('tasks');
  });

  test('should pluralize special plural types', () => {
    expect(pluralizeType('vulnerability')).toEqual('vulns');
  });
});

describe('normalizeType function tests', () => {


  test('should pass through unknown types', () => {
    // @ts-expect-error
    expect(normalizeType('foo')).toEqual('foo');
  });

  test('should pass through undefined', () => {
    expect(normalizeType()).toBeUndefined();
  });
});

describe('apiType function tests', () => {


  test('should pass through unknown types', () => {
    // @ts-expect-error
    expect(apiType('foo')).toEqual('foo');
  });

  test('should pass through undefined', () => {
    expect(apiType()).toBeUndefined();
  });
});

describe('typeName function tests', () => {
  test('should return Unknown unknown types', () => {
    // @ts-expect-error
    expect(typeName('foo')).toEqual('Unknown');
    expect(typeName()).toEqual('Unknown');
  });

});

describe('resourceType function tests', () => {
  test('should return undefined for undefined or empty type', () => {
    expect(resourceType(undefined)).toBeUndefined();
    // @ts-expect-error
    expect(resourceType('')).toBeUndefined();
  });

  test('should return resource type for known types', () => {
    expect(resourceType('certbund')).toEqual('cert_bund_adv');
    expect(resourceType('cpe')).toEqual('cpe');
    expect(resourceType('cve')).toEqual('cve');
    expect(resourceType('dfncert')).toEqual('dfn_cert_adv');
    expect(resourceType('operatingsystem')).toEqual('os');
    expect(resourceType('host')).toEqual('host');
    expect(resourceType('nvt')).toEqual('nvt');
    expect(resourceType('scanconfig')).toEqual('config');
  });

  test('should support other valid resource types', () => {
    expect(resourceType('credential')).toEqual('credential');
    expect(resourceType('filter')).toEqual('filter');
    expect(resourceType('portlist')).toEqual('port_list');
    expect(resourceType('report')).toEqual('report');
    expect(resourceType('reportconfig')).toEqual('report_config');
    expect(resourceType('reportformat')).toEqual('report_format');
    expect(resourceType('target')).toEqual('target');
    expect(resourceType('task')).toEqual('task');
    expect(resourceType('tlscertificate')).toEqual('tls_certificate');
    expect(resourceType('vulnerability')).toEqual('vuln');
  });


  test('should pass through unknown types', () => {
    // @ts-expect-error
    expect(resourceType('foo')).toEqual('foo');
    // @ts-expect-error
    expect(resourceType('bar')).toEqual('bar');
  });
});

describe('entityURL function tests', () => {
  test.each([
    {type: 'task' as EntityType, id: '1', expected: '/task/1'},
    {type: 'scanconfig' as EntityType, id: '2', expected: '/scan-config/2'},
    {type: 'scopereport' as EntityType, id: '3', expected: '/scope-report/3'},
  ])('should build entity URLs for $type', ({type, id, expected}) => {
    expect(entityURL(type, id)).toEqual(expected);
  });
});

/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {
  fetchNativeHosts,
  nativeHostsQueryFromFilter,
} from 'gmp/native-api/hosts';
import {
  fetchNativeOperatingSystems,
  nativeOperatingSystemsQueryFromFilter,
} from 'gmp/native-api/operating-systems';
import {
  fetchNativeReportFormats,
  nativeReportFormatsQueryFromFilter,
} from 'gmp/native-api/report-formats';
import {
  fetchNativeVulnerabilities,
  nativeVulnerabilitiesQueryFromFilter,
} from 'gmp/native-api/vulnerabilities';

const createNativeHttp = () => ({
  buildUrl: testing.fn((path: string) => `https://yafvs.example/${path}`),
  session: {token: 'test-token', jwt: 'jwt-token'},
});

const stubEmptyCollection = () => {
  testing.stubGlobal(
    'fetch',
    testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 0},
        items: [],
      }),
      ok: true,
      status: 200,
    }),
  );
};

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native structured collection filters', () => {
  test('preserves the vulnerability UUID criterion as an exact aggregate identifier', async () => {
    const vulnerabilityId = '1.3.6.1.4.1.25623.1.0.900001';
    const query = nativeVulnerabilitiesQueryFromFilter(
      Filter.fromString(`uuid=${vulnerabilityId} rows=25 first=1`),
    );
    expect(query.vulnerabilityId).toBe(vulnerabilityId);
    expect(query.filter).toBe('');
    stubEmptyCollection();
    const gmp = createNativeHttp();

    await fetchNativeVulnerabilities(gmp, query);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/vulnerabilities', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: query.sort,
      filter: '',
      vulnerability_id: vulnerabilityId,
    });
  });

  test('preserves exact host names', async () => {
    const name = '192.0.2.10';
    const query = nativeHostsQueryFromFilter(
      Filter.fromString(`name=${name} rows=25 first=1`),
    );
    expect(query.name).toBe(name);
    expect(query.filter).toBe('');
    stubEmptyCollection();
    const gmp = createNativeHttp();

    await fetchNativeHosts(gmp, query);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/hosts', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: query.sort,
      filter: '',
      name,
    });
  });

  test('preserves exact operating-system names', async () => {
    const name = 'cpe:/o:example:system:1';
    const query = nativeOperatingSystemsQueryFromFilter(
      Filter.fromString(`name=${name} rows=25 first=1`),
    );
    expect(query.name).toBe(name);
    expect(query.filter).toBe('');
    stubEmptyCollection();
    const gmp = createNativeHttp();

    await fetchNativeOperatingSystems(gmp, query);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/operating-systems', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: query.sort,
      filter: '',
      name,
    });
  });

  test('preserves the predefined report-format criterion', async () => {
    const query = nativeReportFormatsQueryFromFilter(
      Filter.fromString('predefined=1 rows=25 first=1'),
    );
    expect(query.predefined).toBe('1');
    expect(query.filter).toBe('');
    stubEmptyCollection();
    const gmp = createNativeHttp();

    await fetchNativeReportFormats(gmp, query);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-formats', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: query.sort,
      filter: '',
      predefined: '1',
    });
  });
});

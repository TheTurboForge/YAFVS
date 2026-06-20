/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Nvt from 'gmp/models/nvt';
import {fetchNativeNvt, fetchNativeNvts} from 'gmp/native-api/nvts';
import {loadEntity} from 'web/store/entities/nvts';

const createGmp = ({
  jwt,
  token = 'test-token',
}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API NVT catalog', () => {
  test('fetches top-level NVTs as inherited models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-created',
          filter: 'ssh',
        },
        items: [
          {
            id: '1.3.6.1.4.1.25623.1.0.10330',
            oid: '1.3.6.1.4.1.25623.1.0.10330',
            name: 'SSH Brute Force Logins With Default Credentials',
            family: 'Brute force attacks',
            severity: 7.5,
            qod: 80,
            qod_type: 'remote_banner',
            solution_type: 'Mitigation',
            solution_method: 'VendorFix',
            solution: 'Disable default credentials.',
            tags: 'summary=Finds weak SSH credentials.|impact=Login is possible.',
            cve_refs: 1,
            cves: ['CVE-2026-10001'],
            cert_refs: ['dfn-cert:DFN-CERT-2026-001'],
            xrefs: ['url:https://example.test/advisory'],
            max_epss: {
              score: 0.42,
              percentile: 0.91,
              cve: 'CVE-2026-10001',
              severity: 7.5,
            },
            max_severity: {
              score: 0.32,
              percentile: 0.81,
              cve: 'CVE-2026-10002',
              severity: 8.1,
            },
            created_at: '2026-06-18T20:00:00Z',
            modified_at: '2026-06-19T07:00:00Z',
            updated_at: '2026-06-19T07:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeNvts(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-created',
      filter: 'ssh',
    });

    const nvt = response.nvts[0];
    expect(response.counts.filtered).toEqual(1);
    expect(nvt.id).toEqual('1.3.6.1.4.1.25623.1.0.10330');
    expect(nvt.name).toEqual('SSH Brute Force Logins With Default Credentials');
    expect(nvt.family).toEqual('Brute force attacks');
    expect(nvt.severity).toEqual(7.5);
    expect(nvt.qod?.value).toEqual(80);
    expect(nvt.qod?.type).toEqual('remote_banner');
    expect(nvt.solution?.type).toEqual('Mitigation');
    expect(nvt.solution?.description).toEqual('Disable default credentials.');
    expect(nvt.tags.summary).toEqual('Finds weak SSH credentials.');
    expect(nvt.cves).toEqual(['CVE-2026-10001']);
    expect(nvt.certs).toEqual([{id: 'DFN-CERT-2026-001', type: 'dfn-cert'}]);
    expect(nvt.xrefs).toEqual([
      {ref: 'https://example.test/advisory', type: 'url'},
    ]);
    expect(nvt.epss?.maxEpss?.score).toEqual(0.42);
    expect(nvt.epss?.maxSeverity?.cve?.id).toEqual('CVE-2026-10002');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/nvts', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-created',
      filter: 'ssh',
    });
    expect(fetchMock).toHaveBeenCalledWith('https://turbovas.example/api/v1/nvts', {
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer jwt-token',
      },
    });
  });

  test('fetches one NVT and folds detail text into inherited tag fields', async () => {
    const id = '1.3.6.1.4.1.25623.1.1.9.2026.29807996710206';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        oid: id,
        name: 'Fedora: Security Advisory',
        comment: 'Native detail comment',
        family: 'Fedora Local Security Checks',
        severity: 5.0,
        qod: 97,
        qod_type: 'package',
        solution_type: 'VendorFix',
        solution: 'Please install the updated package(s).',
        summary: 'Native summary',
        insight: 'Native insight',
        affected: 'Native affected package',
        impact: 'Native impact',
        detection: 'Native detection method',
        tags: 'cvss_base_vector=AV:N/AC:L/Au:N/C:P/I:N/A:N',
        cves: ['CVE-2026-10001'],
        xrefs: ['url:https://example.test/advisory'],
        created_at: '2026-05-22T05:24:06Z',
        modified_at: '2026-05-22T05:24:06Z',
        updated_at: '2026-05-22T05:24:06Z',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeNvt(gmp, id);

    const nvt = response.nvt;
    expect(nvt.id).toEqual(id);
    expect(nvt.comment).toEqual('Native detail comment');
    expect(nvt.tags.cvss_base_vector).toEqual('AV:N/AC:L/Au:N/C:P/I:N/A:N');
    expect(nvt.tags.summary).toEqual('Native summary');
    expect(nvt.tags.insight).toEqual('Native insight');
    expect(nvt.tags.affected).toEqual('Native affected package');
    expect(nvt.tags.impact).toEqual('Native impact');
    expect(nvt.tags.vuldetect).toEqual('Native detection method');
    expect(nvt.solution?.type).toEqual('VendorFix');
    expect(nvt.solution?.description).toEqual(
      'Please install the updated package(s).',
    );
    expect(nvt.xrefs).toEqual([
      {ref: 'https://example.test/advisory', type: 'url'},
    ]);
    expect(gmp.buildUrl).toHaveBeenCalledWith(`api/v1/nvts/${id}`, {
      token: 'test-token',
    });
  });

  test('loads inherited detail context before overlaying native Information fields', async () => {
    const id = '1.3.6.1.4.1.25623.1.1.9.2026.29807996710206';
    const calls: string[] = [];
    const inherited = Nvt.fromElement({
      _id: id,
      writable: 1,
      nvt: {
        _oid: id,
        name: 'Inherited NVT',
        family: 'Inherited family',
        cvss_base: 1.0,
        default_timeout: '300',
        timeout: '600',
        tags: 'summary=Inherited summary|vuldetect=Inherited detection',
        preferences: {
          preference: [
            {
              id: 1,
              name: 'retained-pref',
              hr_name: 'Retained preference',
              type: 'entry',
              value: 'retained',
            },
          ],
        },
      },
      user_tags: {
        tag: [{_id: 'tag-1', name: 'Retained tag', value: 'true'}],
      },
    });
    const fetchMock = testing.fn().mockImplementation(() => {
      calls.push('native');
      return Promise.resolve({
        json: testing.fn().mockResolvedValue({
          id,
          oid: id,
          name: 'Native NVT',
          comment: 'native comment',
          family: 'Native family',
          severity: 5.0,
          qod: 97,
          qod_type: 'package',
          solution_type: 'VendorFix',
          solution: 'Please install the updated package(s).',
          summary: 'Native summary',
          insight: 'Native insight',
          affected: 'Native affected package',
          impact: 'Native impact',
          detection: 'Native detection method',
          tags: 'cvss_base_vector=AV:N/AC:L/Au:N/C:P/I:N/A:N',
          cves: ['CVE-2026-10001'],
          xrefs: ['url:https://example.test/advisory'],
        }),
        ok: true,
        status: 200,
      });
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      nvt: {
        get: testing.fn().mockImplementation(() => {
          calls.push('gmp');
          return Promise.resolve({data: inherited});
        }),
      },
    };
    const actions: Array<{type: string; data?: Nvt}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        nvt: {
          byId: {},
          errors: {},
          isLoading: {},
        },
      },
    });

    await loadEntity(gmp)(id)(dispatch, getState);

    const success = actions.find(
      action => action.type === 'ENTITY_LOADING_SUCCESS',
    );
    const nvt = success?.data;
    expect(calls).toEqual(['gmp', 'native']);
    expect(gmp.nvt.get).toHaveBeenCalledWith({id});
    expect(nvt).toBeInstanceOf(Nvt);
    expect(nvt?.name).toEqual('Native NVT');
    expect(nvt?.comment).toEqual('native comment');
    expect(nvt?.family).toEqual('Native family');
    expect(nvt?.severity).toEqual(5.0);
    expect(nvt?.qod?.value).toEqual(97);
    expect(nvt?.tags.summary).toEqual('Native summary');
    expect(nvt?.tags.vuldetect).toEqual('Native detection method');
    expect(nvt?.tags.cvss_base_vector).toEqual('AV:N/AC:L/Au:N/C:P/I:N/A:N');
    expect(nvt?.preferences[0].name).toEqual('retained-pref');
    expect(nvt?.defaultTimeout).toEqual(300);
    expect(nvt?.timeout).toEqual(600);
    expect(nvt?.userTags?.[0].name).toEqual('Retained tag');
    expect(nvt?.isWritable()).toEqual(true);
  });
});

/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import Result from 'gmp/models/result';
import {fetchNativeResult, fetchNativeResults} from 'gmp/native-api/reports';
import {loadEntities, loadEntity} from 'web/store/entities/results';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const createGmp = ({
  jwt,
  token = 'test-token',
}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://yafvs.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API result list', () => {
  test('fetches top-level results as inherited Result models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-severity', filter: ''},
        items: [
          {
            id: 'result-1',
            host: '192.168.178.42',
            host_asset_id: 'host-asset-1',
            hostname: 'workstation.local',
            port: '443/tcp',
            nvt_oid: '1.3.6.1.4.1.25623.1.0.900001',
            name: 'Example vulnerability',
            nvt_family: 'General',
            description_excerpt: 'Example detection text',
            solution_type: 'VendorFix',
            solution: 'Install the vendor fix.',
            severity: 7.5,
            qod: 80,
            scan_nvt_version: '20260618T1200',
            created_at: '2026-06-18T20:00:00Z',
            report: {id: 'report-1', name: 'Full and fast'},
            task: {id: 'task-1', name: 'LAN scan'},
            source_report_id: 'report-1',
            raw_evidence_href: '/result/result-1',
            overrides: [
              {
                id: 'override-1',
                nvt: {
                  id: '1.3.6.1.4.1.25623.1.0.900001',
                  name: 'Example vulnerability',
                  type: 'nvt',
                },
                text: 'Accepted risk for this host',
                text_excerpt: false,
                hosts: '192.168.178.42',
                port: '443/tcp',
                severity: 7.5,
                new_severity: -1,
                active: true,
                modified_at: '2026-06-18T21:00:00Z',
              },
            ],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeResults(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-severity',
      filter: '',
    });

    const result = response.results[0];
    expect(response.counts.filtered).toEqual(1);
    expect(result.id).toEqual('result-1');
    expect(result.name).toEqual('Example vulnerability');
    expect(result.description).toEqual('Example detection text');
    expect(result.severity).toEqual(7.5);
    expect(result.qod?.value).toEqual(80);
    expect(result.host?.name).toEqual('192.168.178.42');
    expect(result.host?.id).toEqual('host-asset-1');
    expect(result.host?.hostname).toEqual('workstation.local');
    expect(result.port).toEqual('443/tcp');
    expect(result.information?.id).toEqual('1.3.6.1.4.1.25623.1.0.900001');
    expect(result.information?.name).toEqual('Example vulnerability');
    expect(
      (result.information as {solution?: {type?: string}})?.solution?.type,
    ).toEqual('VendorFix');
    expect(result.report?.id).toEqual('report-1');
    expect(result.task?.id).toEqual('task-1');
    expect(result.scan_nvt_version).toEqual('20260618T1200');
    expect(result.overrides).toHaveLength(1);
    expect(result.overrides[0].id).toEqual('override-1');
    expect(result.overrides[0].isActive()).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/results', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-severity',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/results',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches one result from the native detail endpoint', async () => {
    const id = '9d77c6b6-dcb2-4a38-87f7-3bb77cf60cf1';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        host: '192.168.178.42',
        host_asset_id: '77777777-7777-4777-8777-777777777777',
        hostname: 'workstation.local',
        port: '443/tcp',
        nvt_oid: '1.3.6.1.4.1.25623.1.0.900001',
        name: 'Example vulnerability',
        nvt_family: 'General',
        description_excerpt: 'Example detection text',
        description: 'Full native result description',
        summary: 'Native summary',
        insight: 'Native insight',
        affected: 'Native affected software',
        impact: 'Native impact',
        detection: 'Native detection method',
        solution_type: 'VendorFix',
        solution: 'Install the vendor fix.',
        max_epss: {
          score: 0.91,
          percentile: 0.98,
          cve: 'CVE-2026-0001',
          severity: 7.5,
        },
        max_severity: {
          score: 0.42,
          percentile: 0.77,
          cve: 'CVE-2026-0002',
          severity: 9.8,
        },
        severity: 7.5,
        qod: 80,
        scan_nvt_version: '20260618T1200',
        created_at: '2026-06-18T20:00:00Z',
        report: {id: 'report-1', name: 'Full and fast'},
        task: {id: 'task-1', name: 'LAN scan'},
        source_report_id: 'report-1',
        raw_evidence_href: `/result/${id}`,
        user_tags: [
          {
            id: 'tag-1',
            name: 'reviewed',
            value: 'yes',
            comment: 'Operator triage tag',
          },
        ],
        overrides: [
          {
            id: 'override-1',
            nvt: {
              id: '1.3.6.1.4.1.25623.1.0.900001',
              name: 'Example vulnerability',
              type: 'nvt',
            },
            text: 'Temporary accepted risk',
            text_excerpt: false,
            hosts: '192.168.178.42',
            port: '443/tcp',
            severity: 7.5,
            new_severity: -1,
            active: true,
            modified_at: '2026-06-18T21:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeResult(gmp, id);

    expect(response.result).toBeInstanceOf(Result);
    expect(response.result.id).toEqual(id);
    expect(response.result.name).toEqual('Example vulnerability');
    expect(response.result.description).toEqual(
      'Full native result description',
    );
    expect(response.result.host?.id).toEqual(
      '77777777-7777-4777-8777-777777777777',
    );
    expect(
      (response.result.information as {tags?: {summary?: string}})?.tags
        ?.summary,
    ).toEqual('Native summary');
    expect(
      (response.result.information as {tags?: {vuldetect?: string}})?.tags
        ?.vuldetect,
    ).toEqual('Native detection method');
    expect(
      (response.result.information as {tags?: {affected?: string}})?.tags
        ?.affected,
    ).toEqual('Native affected software');
    expect(
      (response.result.information as {tags?: {impact?: string}})?.tags?.impact,
    ).toEqual('Native impact');
    expect(
      (response.result.information as {tags?: {insight?: string}})?.tags
        ?.insight,
    ).toEqual('Native insight');
    expect(
      (response.result.information as {epss?: {maxEpss?: {score?: number}}})
        ?.epss?.maxEpss?.score,
    ).toEqual(0.91);
    expect(
      (
        response.result.information as {
          epss?: {maxEpss?: {cve?: {id?: string}}};
        }
      )?.epss?.maxEpss?.cve?.id,
    ).toEqual('CVE-2026-0001');
    expect(
      (
        response.result.information as {
          epss?: {maxSeverity?: {cve?: {severity?: number}}};
        }
      )?.epss?.maxSeverity?.cve?.severity,
    ).toEqual(9.8);
    expect(response.result.report?.id).toEqual('report-1');
    expect(response.result.task?.name).toEqual('LAN scan');
    expect(response.result.userTags).toHaveLength(1);
    expect(response.result.userTags[0].name).toEqual('reviewed');
    expect(response.result.userTags[0].value).toEqual('yes');
    expect(response.result.overrides).toHaveLength(1);
    expect(response.result.overrides[0].id).toEqual('override-1');
    expect(response.result.overrides[0].isActive()).toEqual(true);
    expect(response.result.overrides[0].text).toEqual(
      'Temporary accepted risk',
    );
    expect(response.result.overrides[0].newSeverity).toEqual(-1);
    expect(gmp.buildUrl).toHaveBeenCalledWith(`api/v1/results/${id}`, {
      token: 'test-token',
    });
  });

  test('loads the result store through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort-reverse=severity');
    const rootState = createState('result', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: '-severity', filter: ''},
        items: [
          {
            id: 'result-1',
            host: '192.168.178.42',
            port: '443/tcp',
            nvt_oid: '1.3.6.1.4.1.25623.1.0.900001',
            name: 'Example vulnerability',
            severity: 7.5,
            qod: 80,
            report: {id: 'report-1', name: 'Full and fast'},
            task: {id: 'task-1', name: 'LAN scan'},
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/results', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: '-severity',
      filter: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0]).toBeInstanceOf(Result);
    expect(successAction.data[0].name).toEqual('Example vulnerability');
  });

  test('loads native detail without calling inherited GMP result detail', async () => {
    const id = '9d77c6b6-dcb2-4a38-87f7-3bb77cf60cf1';
    const calls: string[] = [];
    const fetchMock = testing.fn().mockImplementation(() => {
      calls.push('native');
      return Promise.resolve({
        json: testing.fn().mockResolvedValue({
          id,
          host: '192.168.178.43',
          host_asset_id: '77777777-7777-4777-8777-777777777777',
          hostname: 'workstation.local',
          port: '443/tcp',
          nvt_oid: '1.3.6.1.4.1.25623.1.0.900001',
          name: 'Native result metadata',
          nvt_family: 'Native family',
          description_excerpt: 'Native excerpt only',
          description: 'Full native result description',
          summary: 'Native summary',
          insight: 'Native insight',
          affected: 'Native affected software',
          impact: 'Native impact',
          detection: 'Native detection method',
          solution_type: 'VendorFix',
          solution: 'Native solution',
          severity: 7.5,
          qod: 80,
          scan_nvt_version: '20260618T1200',
          created_at: '2026-06-18T20:00:00Z',
          report: {id: 'report-native', name: 'Native report'},
          task: {id: 'task-native', name: 'Native task'},
          source_report_id: 'report-native',
          raw_evidence_href: `/result/${id}`,
        }),
        ok: true,
        status: 200,
      });
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      result: {
        get: testing.fn().mockRejectedValue(new Error('unexpected GMP call')),
      },
    };
    const actions: Array<{type: string; data?: Result}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        result: {
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
    const result = success?.data;
    expect(calls).toEqual(['native']);
    expect(gmp.result.get).not.toHaveBeenCalled();
    expect(result).toBeInstanceOf(Result);
    expect(result?.description).toEqual('Full native result description');
    expect(
      (result?.information as {tags?: {summary?: string}} | undefined)?.tags
        ?.summary,
    ).toEqual('Native summary');
    expect(
      (result?.information as {tags?: {vuldetect?: string}} | undefined)?.tags
        ?.vuldetect,
    ).toEqual('Native detection method');
    expect(
      (result?.information as {tags?: {affected?: string}} | undefined)?.tags
        ?.affected,
    ).toEqual('Native affected software');
    expect(
      (result?.information as {tags?: {impact?: string}} | undefined)?.tags
        ?.impact,
    ).toEqual('Native impact');
    expect(
      (result?.information as {tags?: {insight?: string}} | undefined)?.tags
        ?.insight,
    ).toEqual('Native insight');
    expect(result?.host?.name).toEqual('192.168.178.43');
    expect(result?.host?.id).toEqual('77777777-7777-4777-8777-777777777777');
    expect(result?.port).toEqual('443/tcp');
    expect(result?.severity).toEqual(7.5);
    expect(result?.qod?.value).toEqual(80);
    expect(result?.report?.id).toEqual('report-native');
    expect(result?.task?.name).toEqual('Native task');
    expect(result?.scan_nvt_version).toEqual('20260618T1200');
  });

  test('reports native detail errors without inherited GMP fallback', async () => {
    const id = '9d77c6b6-dcb2-4a38-87f7-3bb77cf60cf1';
    const calls: string[] = [];
    const nativeError = new Error('native detail failed');
    testing.stubGlobal(
      'fetch',
      testing.fn().mockImplementation(() => {
        calls.push('native');
        return Promise.reject(nativeError);
      }),
    );
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      result: {
        get: testing.fn().mockRejectedValue(new Error('unexpected GMP call')),
      },
    };
    const actions: Array<{type: string; data?: Result; error?: Error}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        result: {
          byId: {},
          errors: {},
          isLoading: {},
        },
      },
    });

    await loadEntity(gmp)(id)(dispatch, getState);

    const error = actions.find(
      action => action.type === 'ENTITY_LOADING_ERROR',
    );
    expect(calls).toEqual(['native']);
    expect(gmp.result.get).not.toHaveBeenCalled();
    expect(error?.error).toBe(nativeError);
  });
});

/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {readFileSync} from 'node:fs';
import {ScopeReportsCommand, ScopesCommand} from 'gmp/commands/scopes';
import {createActionResultResponse, createHttp} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
  const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
    buildUrl: ReturnType<typeof testing.fn>;
    session: ReturnType<typeof createSession>;
  };
  fakeHttp.buildUrl = testing.fn(
    (path: string) => `https://yafvs.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('ScopesCommand tests', () => {
  test('should not contain legacy scope command paths', () => {
    const source = readFileSync(
      new URL('../scopes.ts', import.meta.url),
      'utf8',
    );

    expect(source).not.toContain('create_scope');
    expect(source).not.toContain('modify_scope');
    expect(source).not.toContain('delete_scope');
    expect(source).not.toContain('get_scopes');
    expect(source).not.toContain('canUseNativeApi');
    expect(source).not.toContain('HttpCommand');
  });

  test('should fetch scopes through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        items: [
          {
            id: 'scope-1',
            name: 'Production',
            comment: 'native scope',
            protection_requirement: 'high',
            protection_requirement_label: 'High',
            target_count: 2,
            host_count: 5,
            scope_report_count: 1,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScopesCommand(fakeHttp);
    const result = await cmd.get();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scopes', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: '',
    });
    expect(result.data[0].id).toEqual('scope-1');
    expect(result.data[0].name).toEqual('Production');
    expect(result.data[0].protectionRequirement).toEqual('high');
  });

  test('should fetch one scope through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'scope-1',
        name: 'Production',
        protection_requirement: 'normal',
        protection_requirement_label: 'Normal',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScopesCommand(fakeHttp);
    const result = await cmd.getOne('scope-1');

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scopes/scope-1', {
      token: 'test-token',
    });
    expect(result.data?.id).toEqual('scope-1');
    expect(result.data?.name).toEqual('Production');
  });

  test('should create scope through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'scope-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScopesCommand(fakeHttp);
    const result = await cmd.create({
      name: 'New Scope',
      protectionRequirement: 'normal',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scopes');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/scopes',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          name: 'New Scope',
          protection_requirement: 'normal',
        }),
      },
    );
    expect(result.data.id).toEqual('scope-id');
  });

  test('should not fall back to GMP for unexpected native scope create payloads', async () => {
    const response = createActionResultResponse({id: 'scope-id'});
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ScopesCommand(fakeHttp);
    expect(() =>
      cmd.create({
        id: 'unexpected-scope-id',
        name: 'New Scope',
        protectionRequirement: 'normal',
      }),
    ).toThrow('Native scope create received unsupported payload shape');

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should modify scope metadata and membership through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'scope-id'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScopesCommand(fakeHttp);
    const result = await cmd.modify({
      id: 'scope-id',
      name: 'Updated Scope',
      comment: 'metadata and membership',
      protectionRequirement: 'high',
      targetIds: ['11111111-1111-1111-1111-111111111111'],
      hostIds: [],
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scopes/scope-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/scopes/scope-id',
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          name: 'Updated Scope',
          comment: 'metadata and membership',
          protection_requirement: 'high',
          target_ids: ['11111111-1111-1111-1111-111111111111'],
          host_ids: [],
        }),
      },
    );
    expect(result.data.id).toEqual('scope-id');
  });

  test('should not fall back to GMP for unexpected native scope modify payloads', async () => {
    const response = createActionResultResponse({id: 'scope-id'});
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ScopesCommand(fakeHttp);
    expect(() =>
      cmd.modify({
        id: 'scope-id',
        name: 'Updated Scope',
        comment: 'metadata and membership',
        protectionRequirement: 'high',
        targetIds: ['11111111-1111-1111-1111-111111111111'],
        hostIds: [],
        unexpected: true,
      } as unknown as Parameters<ScopesCommand['modify']>[0]),
    ).toThrow('Native scope modify received unsupported payload shape');

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should delete scope through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 204,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScopesCommand(fakeHttp);
    await cmd.delete({id: 'scope-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scopes/scope-id');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/scopes/scope-id',
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should not fall back to GMP when native scope delete fails', async () => {
    const response = createActionResultResponse({id: 'fallback-scope-id'});
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ScopesCommand(fakeHttp);

    await expect(cmd.delete({id: 'scope-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should generate scope reports through native API when available', async () => {
    const response = createActionResultResponse({id: 'unused'});
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: testing.fn().mockResolvedValue({
        id: 'scope-report-id',
        name: 'Generated scope report',
        status: 'Done',
        scope: {id: 'scope-id', name: 'Scope'},
        protection_requirement: 'normal',
        source_report_count: 0,
        source_target_count: 0,
        member_host_count: 0,
        evidence_host_count: 0,
        missing_host_count: 0,
        result_count: 0,
        vulnerability_count: 0,
        severity: {},
        max_severity: 0,
        excluded_candidate_host_count: 0,
        metrics_summary: {},
        sources: [],
      }),
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScopesCommand(fakeHttp);
    await cmd.generateReport({id: 'scope-id'});

    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/scopes/scope-id/reports',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should not fall back to GMP when native scope report generation fails', async () => {
    const response = createActionResultResponse({id: 'unused'});
    const fetchMock = testing.fn().mockResolvedValue({ok: false, status: 409});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';

    const cmd = new ScopesCommand(fakeHttp);
    await expect(cmd.generateReport({id: 'scope-id'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should fetch scope reports through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-creation_time',
          filter: '',
        },
        items: [
          {
            id: 'scope-report-id',
            name: 'Production scope report',
            scope: {id: 'scope-id', name: 'Production'},
            protection_requirement: 'high',
            source_report_count: 1,
            member_host_count: 2,
            evidence_host_count: 1,
            missing_host_count: 1,
            result_count: 4,
            vulnerability_count: 3,
            severity: {high: 1, medium: 1, low: 1, log: 1, false_positive: 0},
            max_severity: 8.1,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScopeReportsCommand(fakeHttp);
    const result = await cmd.get();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scope-reports', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-creation_time',
      filter: '',
    });
    expect(result.data[0].id).toEqual('scope-report-id');
    expect(result.data[0].scopeId).toEqual('scope-id');
    expect(result.meta?.counts.filtered).toEqual(1);
  });

  test('should fetch scoped filtered scope-report lists through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-creation_time',
          filter: 'Production',
        },
        items: [
          {
            id: 'scope-report-id',
            name: 'Production scope report',
            scope: {id: 'scope-id', name: 'Production'},
            protection_requirement: 'high',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new ScopeReportsCommand(fakeHttp);
    const result = await cmd.get({scopeId: 'scope-id', filter: 'Production'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scope-reports', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-creation_time',
      filter: 'Production',
      scope_id: 'scope-id',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/scope-reports',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data[0].id).toEqual('scope-report-id');
    expect(result.data[0].scopeId).toEqual('scope-id');
  });

  test('should delete scope reports through native API when available', async () => {
    const response = createActionResultResponse({
      action: 'delete',
      id: 'scope-report-id',
    });
    const fetchMock = testing.fn().mockResolvedValue({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';

    const cmd = new ScopeReportsCommand(fakeHttp);
    await cmd.delete({id: 'scope-report-id'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/scope-reports/scope-report-id',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/scope-reports/scope-report-id',
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-YAFVS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });
});

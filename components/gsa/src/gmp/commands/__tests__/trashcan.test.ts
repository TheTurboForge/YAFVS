/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {createResponse, createHttp} from 'gmp/commands/testing';
import TrashCanCommand from 'gmp/commands/trashcan';
import {
  NativeTrashcanEmptyIndeterminateError,
  NativeTrashcanEmptyPreviewChangedError,
} from 'gmp/native-api/trashcan';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const EMPTY_PREVIEW_RESOURCE_TYPES = [
  'configs',
  'alerts',
  'credentials',
  'filters',
  'overrides',
  'port_lists',
  'scanners',
  'schedules',
  'tags',
  'targets',
  'tasks',
  'report_formats',
];
const SNAPSHOT_DIGEST = 'a'.repeat(64);

const emptyPreview = (total: number) => ({
  scope: 'operator' as const,
  snapshot_digest: SNAPSHOT_DIGEST,
  items: EMPTY_PREVIEW_RESOURCE_TYPES.map(resource_type => ({
    resource_type,
    count: resource_type === 'targets' ? total : 0,
  })),
  total,
});

const createNativeTrashcanCommand = () => {
  const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
    buildUrl: ReturnType<typeof testing.fn>;
    session: ReturnType<typeof createSession>;
  };
  fakeHttp.buildUrl = testing.fn(
    (path: string) => `https://yafvs.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  return {cmd: new TrashCanCommand(fakeHttp), fakeHttp};
};

describe('TrashCanCommand tests', () => {
  test.each([
    ['alert', 'alerts'],
    ['credential', 'credentials'],
    ['filter', 'filters'],
    ['override', 'overrides'],
    ['portlist', 'port-lists'],
    ['scanconfig', 'scan-configs'],
    ['scanner', 'scanners'],
    ['schedule', 'schedules'],
    ['tag', 'tags'],
    ['target', 'targets'],
    ['task', 'tasks'],
  ] as const)(
    'should restore supported %s trash entities through native API',
    async (entityType, path) => {
      const fetchMock = testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({id: '1234'}),
        ok: true,
        status: 200,
      });
      testing.stubGlobal('fetch', fetchMock);
      const fakeHttp = createHttp(undefined) as ReturnType<
        typeof createHttp
      > & {
        buildUrl: ReturnType<typeof testing.fn>;
        session: ReturnType<typeof createSession>;
      };
      fakeHttp.buildUrl = testing.fn(
        (path: string) => `https://yafvs.example/${path}`,
      );
      fakeHttp.session = createSession();
      fakeHttp.session.token = 'test-token';
      fakeHttp.session.jwt = 'jwt-token';
      const cmd = new TrashCanCommand(fakeHttp);

      await cmd.restore({id: '1234', entityType});

      expect(fakeHttp.request).not.toHaveBeenCalled();
      expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
        `api/v1/${path}/1234/restore`,
      );
      expect(fetchMock).toHaveBeenCalledWith(
        `https://yafvs.example/api/v1/${path}/1234/restore`,
        {
          method: 'POST',
          credentials: 'include',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            'X-YAFVS-Token': 'test-token',
            Authorization: 'Bearer jwt-token',
          },
          body: JSON.stringify({}),
        },
      );
    },
  );

  test('should reject an untyped restore without a network request', async () => {
    const fakeHttp = createHttp(createResponse({}));
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(cmd.restore({id: '1234'} as never)).rejects.toThrow(
      'Trashcan restore is unavailable for undefined',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject retired report-format restore without a network request', async () => {
    const fakeHttp = createHttp(createResponse({}));
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(
      cmd.restore({id: '1234', entityType: 'reportformat'}),
    ).rejects.toThrow('Trashcan restore is unavailable for reportformat');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject unsupported restore types without a network request', async () => {
    const fakeHttp = createHttp(createResponse({}));
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(cmd.restore({id: '1234', entityType: 'user'})).rejects.toThrow(
      'Trashcan restore is unavailable for user',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should not fall back to GMP when native restore is unavailable', async () => {
    const fakeHttp = createHttp(createResponse({}));
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(
      cmd.restore({id: '1234', entityType: 'filter'}),
    ).rejects.toThrow('Native Trashcan restore is unavailable for filter');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should not fall back to GMP when native restore fails', async () => {
    const response = createResponse({});
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'conflict'}}),
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
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(
      cmd.restore({id: '1234', entityType: 'filter'}),
    ).rejects.toThrow('Native API request failed with status 409');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should preview and empty the trashcan through the native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue(emptyPreview(3)),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          scope: 'operator',
          deleted_total: 3,
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const {cmd, fakeHttp} = createNativeTrashcanCommand();
    fakeHttp.session.jwt = 'jwt-token';

    const preview = await cmd.emptyPreview();
    await cmd.empty({
      expectedTotal: preview.total,
      expectedSnapshotDigest: preview.snapshot_digest,
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/trashcan/empty-preview',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/trashcan/empty',
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://yafvs.example/api/v1/trashcan/empty-preview',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://yafvs.example/api/v1/trashcan/empty',
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
          acknowledge_permanent_deletion: true,
          expected_total: 3,
          expected_snapshot_digest: SNAPSHOT_DIGEST,
        }),
      },
    );
  });

  test.each([
    [
      'missing a canonical resource type',
      () => {
        const preview = emptyPreview(3);
        preview.items.pop();
        return preview;
      },
    ],
    [
      'a duplicate canonical resource type',
      () => {
        const preview = emptyPreview(3);
        preview.items[1] = {...preview.items[0]};
        return preview;
      },
    ],
    [
      'an extra resource type',
      () => {
        const preview = emptyPreview(3);
        preview.items[1] = {resource_type: 'unexpected', count: 0};
        return preview;
      },
    ],
    [
      'a total that does not equal the resource count sum',
      () => ({...emptyPreview(3), total: 4}),
    ],
  ])(
    'rejects a native empty preview with %s',
    async (_description, preview) => {
      const fetchMock = testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue(preview()),
        ok: true,
        status: 200,
      });
      testing.stubGlobal('fetch', fetchMock);
      const {cmd, fakeHttp} = createNativeTrashcanCommand();

      await expect(cmd.emptyPreview()).rejects.toThrow(
        'Native Trashcan empty preview response is invalid',
      );
      expect(fakeHttp.request).not.toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalledTimes(1);
    },
  );

  test('should require a new confirmation when native empty preview changed', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 409,
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
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(
      cmd.empty({expectedTotal: 3, expectedSnapshotDigest: SNAPSHOT_DIGEST}),
    ).rejects.toBeInstanceOf(NativeTrashcanEmptyPreviewChangedError);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  test('should not report native empty success for an indeterminate outcome', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 502,
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
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(
      cmd.empty({expectedTotal: 3, expectedSnapshotDigest: SNAPSHOT_DIGEST}),
    ).rejects.toBeInstanceOf(NativeTrashcanEmptyIndeterminateError);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  test.each([
    ['alert', 'alerts'],
    ['credential', 'credentials'],
    ['filter', 'filters'],
    ['override', 'overrides'],
    ['portlist', 'port-lists'],
    ['scanconfig', 'scan-configs'],
    ['scanner', 'scanners'],
    ['schedule', 'schedules'],
    ['tag', 'tags'],
    ['target', 'targets'],
    ['task', 'tasks'],
  ] as const)(
    'should permanently delete supported %s trash entities through native API',
    async (entityType, path) => {
      const fetchMock = testing.fn().mockResolvedValue({
        ok: true,
        status: 204,
      });
      testing.stubGlobal('fetch', fetchMock);
      const fakeHttp = createHttp(undefined) as ReturnType<
        typeof createHttp
      > & {
        buildUrl: ReturnType<typeof testing.fn>;
        session: ReturnType<typeof createSession>;
      };
      fakeHttp.buildUrl = testing.fn(
        (path: string) => `https://yafvs.example/${path}`,
      );
      fakeHttp.session = createSession();
      fakeHttp.session.token = 'test-token';
      fakeHttp.session.jwt = 'jwt-token';
      const cmd = new TrashCanCommand(fakeHttp);

      await cmd.delete({id: '1234', entityType});

      expect(fakeHttp.request).not.toHaveBeenCalled();
      expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
        `api/v1/${path}/1234/trash`,
      );
      expect(fetchMock).toHaveBeenCalledWith(
        `https://yafvs.example/api/v1/${path}/1234/trash`,
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
    },
  );

  test('should reject retired report-format permanent delete without a network request', async () => {
    const fakeHttp = createHttp(createResponse({}));
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(
      cmd.delete({id: '1234', entityType: 'reportformat'}),
    ).rejects.toThrow(
      'Trashcan permanent delete is unavailable for reportformat',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject an untyped permanent delete without a network request', async () => {
    const fakeHttp = createHttp(createResponse({}));
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(cmd.delete({id: '1234'} as never)).rejects.toThrow(
      'Trashcan permanent delete is unavailable for undefined',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject unsupported permanent delete types without a network request', async () => {
    const fakeHttp = createHttp(createResponse({}));
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(cmd.delete({id: '1234', entityType: 'host'})).rejects.toThrow(
      'Trashcan permanent delete is unavailable for host',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should not fall back to GMP when native permanent delete is unavailable', async () => {
    const fakeHttp = createHttp(createResponse({}));
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(
      cmd.delete({id: '1234', entityType: 'filter'}),
    ).rejects.toThrow(
      'Native Trashcan permanent delete is unavailable for filter',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should not fall back to GMP when supported native trash delete fails', async () => {
    const response = createResponse({});
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
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(
      cmd.delete({id: '1234', entityType: 'filter'}),
    ).rejects.toThrow('Native API request failed with status 409');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should load trashcan rows through native redacted item API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 500, total: 12},
        items: [
          {
            id: '11111111-1111-1111-1111-111111111111',
            resource_type: 'alerts',
            entity_type: 'alert',
            title: 'Alerts',
            name: 'Alert in trash',
          },
          {
            id: '22222222-2222-2222-2222-222222222222',
            resource_type: 'configs',
            entity_type: 'scanconfig',
            title: 'Scan configurations',
            name: 'Scan configuration in trash',
          },
          {
            id: '33333333-3333-3333-3333-333333333333',
            resource_type: 'credentials',
            entity_type: 'credential',
            title: 'Credentials',
            name: 'SSH credential',
            comment: 'redacted row',
          },
          {
            id: '44444444-4444-4444-4444-444444444444',
            resource_type: 'filters',
            entity_type: 'filter',
            title: 'Filters',
            name: 'Filter in trash',
          },
          {
            id: '55555555-5555-5555-5555-555555555555',
            resource_type: 'overrides',
            entity_type: 'override',
            title: 'Overrides',
            name: 'Override in trash',
          },
          {
            id: '66666666-6666-6666-6666-666666666666',
            resource_type: 'port_lists',
            entity_type: 'portlist',
            title: 'Port lists',
            name: 'Port list in trash',
          },
          {
            id: '77777777-7777-7777-7777-777777777777',
            resource_type: 'report_formats',
            entity_type: 'reportformat',
            title: 'Report formats',
            name: 'Report format in trash',
          },
          {
            id: '88888888-8888-8888-8888-888888888888',
            resource_type: 'scanners',
            entity_type: 'scanner',
            title: 'Scanners',
            name: 'Scanner in trash',
          },
          {
            id: '99999999-9999-9999-9999-999999999999',
            resource_type: 'schedules',
            entity_type: 'schedule',
            title: 'Schedules',
            name: 'Schedule in trash',
          },
          {
            id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            resource_type: 'tags',
            entity_type: 'tag',
            title: 'Tags',
            name: 'Tag in trash',
          },
          {
            id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
            resource_type: 'targets',
            entity_type: 'target',
            title: 'Targets',
            name: 'Target without hosts',
          },
          {
            id: 'cccccccc-cccc-cccc-cccc-cccccccccccc',
            resource_type: 'tasks',
            entity_type: 'task',
            title: 'Tasks',
            name: 'Task in trash',
          },
        ],
      }),
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
    const cmd = new TrashCanCommand(fakeHttp);

    const data = await cmd.get();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/trashcan/items', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'resource_type',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/trashcan/items',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(data.data.credentials[0].id).toBe(
      '33333333-3333-3333-3333-333333333333',
    );
    expect(data.data.credentials[0].name).toBe('SSH credential');
    expect(data.data.alerts[0].name).toBe('Alert in trash');
    expect(data.data.scanConfigs[0].name).toBe('Scan configuration in trash');
    expect(data.data.filters[0].name).toBe('Filter in trash');
    expect(data.data.overrides[0].name).toBe('Override in trash');
    expect(data.data.portLists[0].name).toBe('Port list in trash');
    expect(data.data.reportFormats[0].name).toBe('Report format in trash');
    expect(data.data.scanners[0].name).toBe('Scanner in trash');
    expect(data.data.schedules[0].name).toBe('Schedule in trash');
    expect(data.data.tags[0].name).toBe('Tag in trash');
    expect(data.data.targets[0].name).toBe('Target without hosts');
    expect(data.data.tasks[0].entityType).toBe('task');
  });

  test('should not fall back to GMP when native inventory fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 500,
    });
    testing.stubGlobal('fetch', fetchMock);
    const {cmd, fakeHttp} = createNativeTrashcanCommand();

    await expect(cmd.get()).rejects.toThrow(
      'Native API request failed with status 500',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should not fall back to GMP when native inventory is unavailable', async () => {
    const fakeHttp = createHttp(createResponse({}));
    const cmd = new TrashCanCommand(fakeHttp);

    await expect(cmd.get()).rejects.toThrow(
      'Native Trashcan inventory is unavailable',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });
});

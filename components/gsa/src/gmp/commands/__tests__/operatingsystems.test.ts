/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {OperatingSystemsCommand} from 'gmp/commands/os';
import {createHttp} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
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

describe('OperatingSystemsCommand tests', () => {
  test('should reject every read and export path without a native HTTP adapter', async () => {
    const legacyHttp = createHttp(undefined);
    const cmd = new OperatingSystemsCommand(legacyHttp);
    const filter = Filter.fromString('first=1 rows=25 search=linux');
    const error =
      'Operating-system reads and exports require the native HTTP adapter.';

    await expect(cmd.get()).rejects.toThrow(error);
    await expect(cmd.getAll()).rejects.toThrow(error);
    expect(() => cmd.exportByIds(['os-1'])).toThrow(error);
    expect(() => cmd.export([{id: 'os-1'}])).toThrow(error);
    await expect(cmd.exportByFilter(filter)).rejects.toThrow(error);
    expect(legacyHttp.request).not.toHaveBeenCalled();
  });

  test('should fetch operating systems through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-latest_severity',
          filter: 'linux',
        },
        items: [
          {
            id: 'os-1',
            name: 'cpe:/o:example:linux:1.0',
            title: 'Example Linux 1.0',
            latest_severity: 7.5,
            highest_severity: 9.1,
            average_severity: 4.25,
            hosts: 2,
            all_hosts: 3,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new OperatingSystemsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=linux'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('os-1');
    expect(result.data[0].title).toEqual('Example Linux 1.0');
    expect(result.data[0].latestSeverity).toEqual(7.5);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/operating-systems', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'latest_severity',
      filter: 'linux',
    });
  });

  test('should bulk export selected operating systems through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'os-1', name: 'Linux'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'os-2', name: 'BSD'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new OperatingSystemsCommand(fakeHttp);

    const result = await cmd.exportByIds(['os-1', 'os-2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/operating-systems/os-1/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).operating_systems).toEqual([
      {id: 'os-1', name: 'Linux'},
      {id: 'os-2', name: 'BSD'},
    ]);
  });

  test('should bulk export current page filter through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 1,
            total: 3,
            sort: 'latest_severity',
            filter: 'linux',
          },
          items: [{id: 'os-2', name: 'Linux 2'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'os-2', name: 'Linux 2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new OperatingSystemsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=linux');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/operating-systems',
      {
        token: 'test-token',
        page: 2,
        page_size: 1,
        sort: 'latest_severity',
        filter: 'linux',
      },
    );
    expect(JSON.parse(result.data).operating_systems).toEqual([
      {id: 'os-2', name: 'Linux 2'},
    ]);
  });

  test('should bulk export all filtered operating systems through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'latest_severity',
            filter: 'linux',
          },
          items: [{id: 'os-1', name: 'Linux 1'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 500,
            total: 2,
            sort: 'latest_severity',
            filter: 'linux',
          },
          items: [{id: 'os-2', name: 'Linux 2'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'os-1', name: 'Linux 1'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'os-2', name: 'Linux 2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new OperatingSystemsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=linux').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/operating-systems',
      {
        token: 'test-token',
        page: 1,
        page_size: 500,
        sort: 'latest_severity',
        filter: 'linux',
      },
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/operating-systems',
      {
        token: 'test-token',
        page: 2,
        page_size: 500,
        sort: 'latest_severity',
        filter: 'linux',
      },
    );
    expect(JSON.parse(result.data).operating_systems).toEqual([
      {id: 'os-1', name: 'Linux 1'},
      {id: 'os-2', name: 'Linux 2'},
    ]);
  });
});

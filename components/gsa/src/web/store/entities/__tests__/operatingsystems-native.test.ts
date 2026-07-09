/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeOperatingSystem,
  fetchNativeOperatingSystems,
} from 'gmp/native-api/operating-systems';
import Filter from 'gmp/models/filter';
import OperatingSystem from 'gmp/models/os';
import {loadEntities, loadEntity} from 'web/store/entities/operatingsystems';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API operating systems list', () => {
  test('fetches top-level operating systems as inherited OperatingSystem models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-latest_severity', filter: ''},
        items: [
          {
            id: 'f3a25f89-2b6c-4e58-92b2-942c686f9342',
            name: 'cpe:/o:example:linux:1.0',
            title: 'Example Linux 1.0',
            latest_severity: 7.5,
            highest_severity: 9.1,
            average_severity: 4.25,
            hosts: 2,
            all_hosts: 3,
            created_at: '2026-06-18T18:00:00Z',
            modified_at: '2026-06-18T20:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeOperatingSystems(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-latest_severity',
      filter: '',
    });

    const os = response.operatingSystems[0];
    expect(response.counts.filtered).toEqual(1);
    expect(os.id).toEqual('f3a25f89-2b6c-4e58-92b2-942c686f9342');
    expect(os.name).toEqual('cpe:/o:example:linux:1.0');
    expect(os.title).toEqual('Example Linux 1.0');
    expect(os.latestSeverity).toEqual(7.5);
    expect(os.highestSeverity).toEqual(9.1);
    expect(os.averageSeverity).toEqual(4.25);
    expect(os.hosts).toEqual(2);
    expect(os.allHosts).toEqual(3);
    expect(os.isInUse()).toEqual(true);
    expect(os.isWritable()).toEqual(false);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/operating-systems', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-latest_severity',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/operating-systems',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('loads the operating-system store through same-origin native API', async () => {
    const filter = Filter.fromString(
      'first=1 rows=10 sort-reverse=latest_severity',
    );
    const rootState = createState('operatingsystem', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 10,
          total: 1,
          sort: '-latest_severity',
          filter: '',
        },
        items: [
          {
            id: 'f3a25f89-2b6c-4e58-92b2-942c686f9342',
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
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/operating-systems', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: '-latest_severity',
      filter: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0]).toBeInstanceOf(OperatingSystem);
    expect(successAction.data[0].title).toEqual('Example Linux 1.0');
  });

  test('fetches one operating system from the native detail endpoint', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'f3a25f89-2b6c-4e58-92b2-942c686f9342',
        name: 'cpe:/o:example:linux:1.0',
        title: 'Example Linux 1.0',
        latest_severity: 7.5,
        highest_severity: 9.1,
        average_severity: 4.25,
        hosts: 2,
        all_hosts: 3,
        created_at: '2026-06-18T18:00:00Z',
        modified_at: '2026-06-18T20:00:00Z',
        user_tags: [
          {
            id: 'tag-1',
            name: 'Critical OS',
            value: 'true',
            comment: 'watch closely',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeOperatingSystem(
      gmp,
      'f3a25f89-2b6c-4e58-92b2-942c686f9342',
    );

    const os = response.operatingSystem;
    expect(os.id).toEqual('f3a25f89-2b6c-4e58-92b2-942c686f9342');
    expect(os.name).toEqual('cpe:/o:example:linux:1.0');
    expect(os.latestSeverity).toEqual(7.5);
    expect(os.allHosts).toEqual(3);
    expect(os.isWritable()).toEqual(true);
    expect(os.userTags?.length).toEqual(1);
    expect(os.userTags?.[0].name).toEqual('Critical OS');
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/operating-systems/f3a25f89-2b6c-4e58-92b2-942c686f9342',
      {token: 'test-token'},
    );
  });

  test('loads native detail without inherited GMP double-read', async () => {
    const id = 'f3a25f89-2b6c-4e58-92b2-942c686f9342';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'cpe:/o:example:linux:1.0',
        title: 'Example Linux 1.0',
        latest_severity: 7.5,
        highest_severity: 9.1,
        average_severity: 4.25,
        hosts: 2,
        all_hosts: 3,
        user_tags: [
          {
            id: 'tag-1',
            name: 'Critical OS',
            value: 'true',
            comment: 'watch closely',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      operatingsystem: {
        get: testing.fn(),
      },
    };
    const actions: Array<{type: string; data?: OperatingSystem}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        operatingsystem: {
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
    const os = success?.data;
    expect(gmp.operatingsystem.get).not.toHaveBeenCalled();
    expect(os).toBeInstanceOf(OperatingSystem);
    expect(os?.name).toEqual('cpe:/o:example:linux:1.0');
    expect(os?.latestSeverity).toEqual(7.5);
    expect(os?.hosts).toEqual(2);
    expect(os?.isWritable()).toEqual(true);
    expect(os?.userTags?.length).toEqual(1);
    expect(os?.userTags?.[0].name).toEqual('Critical OS');
  });
});

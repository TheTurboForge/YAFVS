/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeHost, fetchNativeHosts} from 'gmp/native-api/hosts';
import Host from 'gmp/models/host';
import {loadEntity} from 'web/store/entities/hosts';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API hosts list', () => {
  test('fetches top-level hosts as inherited Host models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-severity', filter: ''},
        items: [
          {
            id: 'a4be8ecf-4f23-4c83-b0fd-3b65161d652b',
            name: '192.168.178.42',
            comment: 'operator workstation',
            hostname: 'workstation.local',
            ip: '192.168.178.42',
            best_os_cpe: 'cpe:/o:canonical:ubuntu_linux',
            best_os_txt: 'Ubuntu Linux',
            severity: 7.5,
            identifiers: [
              {
                id: 'identifier-ip',
                name: 'ip',
                value: '192.168.178.42',
                source_type: 'Report Host',
                source_id: 'report-1',
                source_data: 'Full and fast',
              },
              {
                id: 'identifier-hostname',
                name: 'hostname',
                value: 'workstation.local',
                source_type: 'Report Host',
                source_id: 'report-1',
                source_data: 'Full and fast',
              },
            ],
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

    const response = await fetchNativeHosts(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-severity',
      filter: '',
    });

    const host = response.hosts[0];
    expect(response.counts.filtered).toEqual(1);
    expect(host.id).toEqual('a4be8ecf-4f23-4c83-b0fd-3b65161d652b');
    expect(host.name).toEqual('192.168.178.42');
    expect(host.comment).toEqual('operator workstation');
    expect(host.hostname).toEqual('workstation.local');
    expect(host.ip).toEqual('192.168.178.42');
    expect(host.os).toEqual('cpe:/o:canonical:ubuntu_linux');
    expect(host.details?.best_os_txt?.value).toEqual('Ubuntu Linux');
    expect(host.severity).toEqual(7.5);
    expect(host.identifiers).toHaveLength(2);
    expect(host.identifiers[0].id).toEqual('identifier-ip');
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/hosts', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-severity',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith('https://turbovas.example/api/v1/hosts', {
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer jwt-token',
      },
    });
  });

  test('fetches one host from the native detail endpoint', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        asset: {
          id: 'a4be8ecf-4f23-4c83-b0fd-3b65161d652b',
          name: '192.168.178.42',
          comment: 'operator workstation',
          hostname: 'workstation.local',
          ip: '192.168.178.42',
          best_os_cpe: 'cpe:/o:canonical:ubuntu_linux',
          best_os_txt: 'Ubuntu Linux',
          severity: 7.5,
          identifiers: [
            {
              id: 'identifier-ip',
              name: 'ip',
              value: '192.168.178.42',
              source_type: 'Report Host',
              source_id: 'report-1',
              source_data: 'Full and fast',
            },
            {
              id: 'identifier-hostname',
              name: 'hostname',
              value: 'workstation.local',
              source_type: 'Report Host',
              source_id: 'report-1',
              source_data: 'Full and fast',
            },
          ],
          created_at: '2026-06-18T18:00:00Z',
          modified_at: '2026-06-18T20:00:00Z',
        },
        identifiers: [
          {
            id: 'identifier-ip',
            name: 'ip',
            value: '192.168.178.42',
            source_type: 'Report Host',
            source_id: 'report-1',
            source_data: 'Full and fast',
          },
          {
            id: 'identifier-os',
            name: 'OS',
            value: 'cpe:/o:canonical:ubuntu_linux',
            source_type: 'Report Host',
            source_id: 'report-1',
            source_data: 'Full and fast',
          },
        ],
        operating_systems: [
          {
            id: 'host-os-1',
            name: 'Ubuntu Linux',
            operating_system_id: 'os-1',
            operating_system_name: 'cpe:/o:canonical:ubuntu_linux',
            source_type: 'Report Host',
            source_id: 'report-1',
            source_data: 'Full and fast',
          },
        ],
        details: [
          {
            name: 'best_os_cpe',
            value: 'cpe:/o:canonical:ubuntu_linux',
          },
          {
            name: 'best_os_txt',
            value: 'Ubuntu Linux',
          },
          {
            name: 'traceroute',
            value: '192.168.178.1,192.168.178.42',
          },
        ],
        user_tags: [
          {
            id: 'tag-1',
            name: 'Datacenter',
            value: 'west',
            comment: 'critical asset',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeHost(
      gmp,
      'a4be8ecf-4f23-4c83-b0fd-3b65161d652b',
    );

    const host = response.host;
    expect(host.id).toEqual('a4be8ecf-4f23-4c83-b0fd-3b65161d652b');
    expect(host.hostname).toEqual('workstation.local');
    expect(host.ip).toEqual('192.168.178.42');
    expect(host.os).toEqual('cpe:/o:canonical:ubuntu_linux');
    expect(host.isWritable()).toEqual(true);
    expect(host.identifiers.map(identifier => identifier.id)).toEqual([
      'identifier-ip',
      'identifier-hostname',
      'identifier-os',
    ]);
    expect(
      host.identifiers.find(identifier => identifier.name === 'OS')?.os?.id,
    ).toEqual('os-1');
    expect(host.userTags?.[0].name).toEqual('Datacenter');
    expect(host.userTags?.[0].value).toEqual('west');
    expect(host.routes?.[0]).toEqual([
      {
        ip: '192.168.178.1',
        id: undefined,
        distance: undefined,
        same_source: 0,
      },
      {
        ip: '192.168.178.42',
        id: undefined,
        distance: undefined,
        same_source: 0,
      },
    ]);
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/hosts/a4be8ecf-4f23-4c83-b0fd-3b65161d652b',
      {token: 'test-token'},
    );
  });

  test('loads native detail without inherited GMP double-read', async () => {
    const id = 'a4be8ecf-4f23-4c83-b0fd-3b65161d652b';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        asset: {
          id,
          name: '192.168.178.42',
          comment: 'operator workstation',
          hostname: 'workstation.local',
          ip: '192.168.178.42',
          best_os_cpe: 'cpe:/o:canonical:ubuntu_linux',
          best_os_txt: 'Ubuntu Linux',
          severity: 7.5,
          identifiers: [
            {
              id: 'identifier-ip',
              name: 'ip',
              value: '192.168.178.42',
              source_type: 'Report Host',
              source_id: 'report-1',
            },
            {
              id: 'identifier-hostname',
              name: 'hostname',
              value: 'workstation.local',
              source_type: 'Report Host',
              source_id: 'report-1',
            },
          ],
        },
        identifiers: [
          {
            id: 'identifier-ip',
            name: 'ip',
            value: '192.168.178.42',
            source_type: 'Report Host',
            source_id: 'report-1',
            source_data: 'Full and fast',
          },
          {
            id: 'identifier-os',
            name: 'OS',
            value: 'cpe:/o:canonical:ubuntu_linux',
            source_type: 'Report Host',
            source_id: 'report-1',
            source_data: 'Full and fast',
          },
        ],
        operating_systems: [
          {
            id: 'host-os-1',
            name: 'Ubuntu Linux',
            operating_system_id: 'os-1',
            operating_system_name: 'cpe:/o:canonical:ubuntu_linux',
            source_type: 'Report Host',
            source_id: 'report-1',
            source_data: 'Full and fast',
          },
        ],
        details: [
          {
            name: 'best_os_txt',
            value: 'Ubuntu Linux',
          },
          {
            name: 'traceroute',
            value: '192.168.178.1,192.168.178.42',
          },
        ],
        user_tags: [
          {
            id: 'tag-1',
            name: 'Datacenter',
            value: 'west',
            comment: 'critical asset',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      host: {
        get: testing.fn(),
      },
    };
    const actions: Array<{type: string; data?: Host}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        host: {
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
    const host = success?.data;
    expect(gmp.host.get).not.toHaveBeenCalled();
    expect(host).toBeInstanceOf(Host);
    expect(host?.name).toEqual('192.168.178.42');
    expect(host?.hostname).toEqual('workstation.local');
    expect(host?.severity).toEqual(7.5);
    expect(host?.details?.best_os_cpe?.value).toEqual(
      'cpe:/o:canonical:ubuntu_linux',
    );
    expect(host?.details?.best_os_txt?.value).toEqual('Ubuntu Linux');
    expect(host?.identifiers.map(identifier => identifier.id)).toEqual([
      'identifier-ip',
      'identifier-hostname',
      'identifier-os',
    ]);
    expect(
      host?.identifiers.find(identifier => identifier.name === 'OS')?.os?.id,
    ).toEqual('os-1');
    expect(host?.isWritable()).toEqual(true);
    expect(host?.userTags?.length).toEqual(1);
    expect(host?.userTags?.[0].name).toEqual('Datacenter');
    expect(host?.userTags?.[0].value).toEqual('west');
  });
});

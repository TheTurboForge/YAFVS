/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeOverride,
  fetchNativeOverrides,
} from 'gmp/native-api/overrides';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API overrides', () => {
  test('fetches top-level overrides as inherited Override models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'text', filter: ''},
        items: [
          {
            id: '9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001',
            owner: {name: 'admin'},
            nvt: {
              id: '1.3.6.1.4.1.25623.1.0.999999',
              name: 'Example NVT',
              type: 'nvt',
            },
            text: 'Accepted compensating control',
            text_excerpt: false,
            hosts: '192.0.2.10',
            port: '443/tcp',
            severity: 7.5,
            new_severity: -1,
            writable: true,
            in_use: false,
            orphan: false,
            active: true,
            permissions: ['get_overrides', 'modify_override'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeOverrides(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'text',
      filter: '',
      active: '1',
      text: 'control',
      taskName: '',
    });

    const override = response.overrides[0];
    expect(response.counts.filtered).toEqual(1);
    expect(override.id).toEqual('9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001');
    expect(override.text).toEqual('Accepted compensating control');
    expect(override.hosts).toEqual(['192.0.2.10']);
    expect(override.port).toEqual('443/tcp');
    expect(override.severity).toEqual(7.5);
    expect(override.newSeverity).toEqual(-1);
    expect(override.nvt?.id).toEqual('1.3.6.1.4.1.25623.1.0.999999');
    expect(override.nvt?.name).toEqual('Example NVT');
    expect(override.isActive()).toEqual(true);
    expect(override.isWritable()).toEqual(true);
    expect(override.userCapabilities.mayEdit('override')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/overrides', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'text',
      filter: '',
      active: '1',
      text: 'control',
      task_name: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/overrides',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches override details with task and result links', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001',
        owner: {name: 'admin'},
        nvt: {
          id: '1.3.6.1.4.1.25623.1.0.999999',
          name: 'Example NVT',
          type: 'nvt',
        },
        text: 'Accepted compensating control',
        active: false,
        task: {
          id: 'f65533d8-b078-441a-b09b-71a7aeb37091',
          name: 'Weekly scan',
          trash: false,
        },
        result: {
          id: '96fbeff5-793f-4e60-92aa-f1c3e40daf0c',
          name: '96fbeff5-793f-4e60-92aa-f1c3e40daf0c',
        },
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const override = await fetchNativeOverride(
      gmp,
      '9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001',
    );

    expect(override.isActive()).toEqual(false);
    expect(override.task?.id).toEqual('f65533d8-b078-441a-b09b-71a7aeb37091');
    expect(override.task?.name).toEqual('Weekly scan');
    expect(override.result?.id).toEqual('96fbeff5-793f-4e60-92aa-f1c3e40daf0c');
  });
});

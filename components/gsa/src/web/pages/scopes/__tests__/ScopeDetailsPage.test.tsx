/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {Route, Routes} from 'react-router';
import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {rendererWith, screen, wait} from 'web/testing';
import {createSession} from 'gmp/testing';
import ScopeDetailsPage from 'web/pages/scopes/ScopeDetailsPage';

const scopePayload = {
  id: 'scope-1',
  name: 'Scope One',
  comment: 'scope comment',
  protection_requirement: 'normal',
  protection_requirement_label: 'Normal',
  target_count: 1,
  host_count: 1,
  scope_report_count: 0,
  targets: [{id: 'target-selected', name: 'Selected Target'}],
  hosts: [{id: 'host-selected', name: 'Selected Host'}],
  candidate_hosts: [],
  scope_reports: [],
};

const targetsPayload = {
  page: {page: 1, page_size: 1000, total: 1, sort: 'name', filter: ''},
  items: [
    {
      id: 'target-native',
      name: 'Native Target',
      hosts: ['192.0.2.10'],
      alive_tests: [],
    },
  ],
};

const hostsPayload = {
  page: {page: 1, page_size: 1000, total: 1, sort: 'name', filter: ''},
  items: [
    {
      id: 'host-native',
      name: 'Native Host',
      hostname: 'native.example',
      ip: '192.0.2.11',
      severity: 0,
    },
  ],
};

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ScopeDetailsPage', () => {
  test('loads target and host selector options through native API', async () => {
    const buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    const fetchMock = testing.fn((url: string) => {
      if (url.endsWith('/api/v1/scopes/scope-1')) {
        return Promise.resolve({
          json: testing.fn().mockResolvedValue(scopePayload),
          ok: true,
          status: 200,
        });
      }
      if (url.endsWith('/api/v1/targets')) {
        return Promise.resolve({
          json: testing.fn().mockResolvedValue(targetsPayload),
          ok: true,
          status: 200,
        });
      }
      if (url.endsWith('/api/v1/hosts')) {
        return Promise.resolve({
          json: testing.fn().mockResolvedValue(hostsPayload),
          ok: true,
          status: 200,
        });
      }
      return Promise.reject(new Error(`Unexpected fetch URL: ${url}`));
    });
    testing.stubGlobal('fetch', fetchMock);
    const targetsGet = testing.fn();
    const hostsGet = testing.fn();
    const gmp = {
      buildUrl,
      session: createSession({token: 'test-token'}),
      targets: {get: targetsGet},
      hosts: {get: hostsGet},
      scopes: {
        modify: testing.fn(),
        generateReport: testing.fn(),
        delete: testing.fn(),
      },
    };
    const {render} = rendererWith({gmp, route: '/scopes/scope-1'});

    render(
      <Routes>
        <Route path="/scopes/:id" element={<ScopeDetailsPage />} />
      </Routes>,
    );

    await screen.findByText('Scope One');
    await wait();

    expect(targetsGet).not.toHaveBeenCalled();
    expect(hostsGet).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith('api/v1/scopes/scope-1', {
      token: 'test-token',
    });
    expect(buildUrl).toHaveBeenCalledWith('api/v1/targets', {
      token: 'test-token',
      page: 1,
      page_size: 1000,
      sort: 'name',
      filter: '',
    });
    expect(buildUrl).toHaveBeenCalledWith('api/v1/hosts', {
      token: 'test-token',
      page: 1,
      page_size: 1000,
      sort: 'name',
      filter: '',
    });
    expect(screen.getByText('Selected Target')).toBeInTheDocument();
    expect(screen.getByText('Selected Host')).toBeInTheDocument();
  });
});

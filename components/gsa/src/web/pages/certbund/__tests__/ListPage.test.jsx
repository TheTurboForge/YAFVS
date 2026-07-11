/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {screen, within, rendererWith, wait} from 'web/testing';
import CollectionCounts from 'gmp/collection/collection-counts';
import CertBundAdv from 'gmp/models/cert-bund';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import CertBundPage from 'web/pages/certbund/ListPage';
import {entitiesLoadingActions} from 'web/store/entities/certbund';
import {defaultFilterLoadingActions} from 'web/store/usersettings/defaultfilters/actions';
import {loadingActions} from 'web/store/usersettings/defaults/actions';

const certBund = CertBundAdv.fromElement({
  _id: 'certbund-1',
  name: 'CERT-Bund-2026-001',
  creation_time: '2026-01-15T10:00:00Z',
  cert_bund_adv: {
    cve_refs: 2,
    severity: 8.1,
    title: 'Example CERT-Bund advisory',
    summary: 'Example summary',
  },
});

const reloadInterval = -1;
const manualUrl = 'test/';

const nativeCertBundItem = {
  id: 'certbund-1',
  name: 'CERT-Bund-2026-001',
  created_at: '2026-01-15T10:00:00Z',
  cve_refs: 2,
  severity: 8.1,
  title: 'Example CERT-Bund advisory',
  summary: 'Example summary',
};

const createGmp = ({
  buildUrl,
  nativeCertBundItems = [nativeCertBundItem],
  getCertBunds = testing.fn().mockResolvedValue({
    data: [certBund],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
  getFilters = testing.fn().mockResolvedValue({
    data: [],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  getSetting = testing.fn().mockResolvedValue({
    filter: null,
  }),
} = {}) => {
  const resolvedBuildUrl =
    buildUrl ?? testing.fn((path, _params) => `https://turbovas.example/${path}`);
  if (buildUrl === undefined) {
    testing.stubGlobal(
      'fetch',
      testing.fn(url => {
        const path = String(url);
        const payload = path.includes('/api/v1/filters')
          ? {
              page: {page: 1, page_size: 10, total: 0, sort: 'name', filter: ''},
              items: [],
            }
          : {
              page: {
                page: 1,
                page_size: 10,
                total: nativeCertBundItems.length,
                sort: '-created',
                filter: '',
              },
              items: nativeCertBundItems,
            };
        return Promise.resolve({
          json: testing.fn().mockResolvedValue(payload),
          ok: true,
          status: 200,
        });
      }),
    );
  }
  return {
    buildUrl: resolvedBuildUrl,
    certbunds: {
      get: getCertBunds,
    },
    filters: {
      get: getFilters,
    },
    settings: {
      manualUrl,
      reloadInterval,
    },
    session: createSession({timezone: 'CET'}),
    user: {currentSettings, getSetting},
  };
};

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('CertBundPage tests', () => {
  test('should render full CertBundPage', async () => {
    const gmp = createGmp();
    const {render, store} = rendererWith({
      gmp,
      capabilities: true,
      store: true,
      router: true,
    });

    const defaultSettingFilter = Filter.fromString('foo=bar');
    store.dispatch(loadingActions.success({rowsperpage: {value: '2'}}));
    store.dispatch(
      defaultFilterLoadingActions.success('certbund', defaultSettingFilter),
    );

    const counts = new CollectionCounts({
      first: 1,
      all: 1,
      filtered: 1,
      length: 1,
      rows: 10,
    });
    const filter = Filter.fromString('first=1 rows=10');
    const loadedFilter = Filter.fromString('first=1 rows=10');
    store.dispatch(
      entitiesLoadingActions.success([certBund], filter, loadedFilter, counts),
    );

    const {baseElement} = render(<CertBundPage />);

    await wait();

    const powerFilter = within(screen.queryPowerFilter());
    const inputs = powerFilter.queryTextInputs();
    const select = powerFilter.getByTestId('powerfilter-select');

    expect(
      screen.getAllByTitle('Help: CERT-Bund Advisories')[0],
    ).toBeInTheDocument();
    expect(inputs[0]).toHaveAttribute('name', 'userFilterString');
    expect(screen.getAllByTitle('Update Filter')[0]).toBeInTheDocument();
    expect(screen.getAllByTitle('Remove Filter')[0]).toBeInTheDocument();
    expect(
      screen.getAllByTitle('Reset to Default Filter')[0],
    ).toBeInTheDocument();
    expect(screen.getAllByTitle('Help: Powerfilter')[0]).toBeInTheDocument();
    expect(screen.getAllByTitle('Edit Filter')[0]).toBeInTheDocument();
    expect(select).toHaveAttribute('title', 'Loaded filter');
    expect(select).toHaveValue('--');
    const header = baseElement.querySelectorAll('th');
    expect(header[0]).toHaveTextContent('Name');
    expect(header[1]).toHaveTextContent('Title');
    expect(header[2]).toHaveTextContent('Created');
    expect(header[3]).toHaveTextContent('CVEs');
    expect(header[4]).toHaveTextContent('Severity');

    const row = baseElement.querySelectorAll('tr');
    expect(row[1]).toHaveTextContent('CERT-Bund-2026-001');
    expect(row[1]).toHaveTextContent('Example CERT-Bund advisory');
    expect(row[1]).toHaveTextContent('2');
  });
});

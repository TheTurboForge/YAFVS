/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {screen, within, rendererWith, wait} from 'web/testing';
import CollectionCounts from 'gmp/collection/collection-counts';
import DfnCertAdv from 'gmp/models/dfn-cert';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import DfnCertPage from 'web/pages/dfncert/ListPage';
import {entitiesLoadingActions} from 'web/store/entities/dfncerts';
import {defaultFilterLoadingActions} from 'web/store/usersettings/defaultfilters/actions';
import {loadingActions} from 'web/store/usersettings/defaults/actions';

const dfnCert = DfnCertAdv.fromElement({
  _id: 'dfncert-1',
  name: 'DFN-CERT-2026-001',
  creation_time: '2026-02-10T09:00:00Z',
  dfn_cert_adv: {
    cve_refs: 1,
    severity: 9.1,
    title: 'Example DFN-CERT advisory',
    summary: {
      __text: 'Example summary',
    },
  },
});

const reloadInterval = -1;
const manualUrl = 'test/';

const createGmp = ({
  getDfnCerts = testing.fn().mockResolvedValue({
    data: [dfnCert],
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
} = {}) => ({
  dfncerts: {
    get: getDfnCerts,
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
});

describe('DfnCertPage tests', () => {
  test('should render full DfnCertPage without dashboard controls', async () => {
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
      defaultFilterLoadingActions.success('dfncert', defaultSettingFilter),
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
      entitiesLoadingActions.success([dfnCert], filter, loadedFilter, counts),
    );

    const {baseElement} = render(<DfnCertPage />);

    await wait();

    const powerFilter = within(screen.queryPowerFilter());
    const inputs = powerFilter.queryTextInputs();
    const select = powerFilter.getByTestId('powerfilter-select');

    expect(
      screen.getAllByTitle('Help: DFN-CERT Advisories')[0],
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
    expect(
      screen.queryByTitle('Add new Dashboard Display'),
    ).not.toBeInTheDocument();
    expect(screen.queryByTitle('Reset to Defaults')).not.toBeInTheDocument();
    expect(screen.queryAllByTestId('grid-item')).toHaveLength(0);

    const header = baseElement.querySelectorAll('th');
    expect(header[0]).toHaveTextContent('Name');
    expect(header[1]).toHaveTextContent('Title');
    expect(header[2]).toHaveTextContent('Created');
    expect(header[3]).toHaveTextContent('CVEs');
    expect(header[4]).toHaveTextContent('Severity');

    const row = baseElement.querySelectorAll('tr');
    expect(row[1]).toHaveTextContent('DFN-CERT-2026-001');
    expect(row[1]).toHaveTextContent('Example DFN-CERT advisory');
    expect(row[1]).toHaveTextContent('1');
  });
});

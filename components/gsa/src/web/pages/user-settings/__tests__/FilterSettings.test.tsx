/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {screen, within, wait, rendererWith, fireEvent} from 'web/testing';
import Capabilities from 'gmp/capabilities/capabilities';
import Filter from 'gmp/models/filter';
import FilterSettings from 'web/pages/user-settings/FilterSettings';

const USER_SETTINGS_DEFAULT_FILTER_LOADING_SUCCESS =
  'USER_SETTINGS_DEFAULT_FILTER_LOADING_SUCCESS';

function createGmpMock() {
  return {
    settings: {manualUrl: 'test/'},
    user: {
      getSetting: testing.fn().mockResolvedValue({data: {value: 'f1'}}),
      saveSetting: testing.fn().mockResolvedValue({data: {value: 'f1'}}),
    },
  };
}

describe('FilterSettings', () => {
  test('renders no filter rows if no filters are present', () => {
    const gmp = createGmpMock();
    const capabilities = new Capabilities([]);
    const {render} = rendererWith({capabilities, gmp, store: true});
    render(<FilterSettings />);
    const rows = screen.getAllByRole('row');
    expect(rows.length).toBe(26);
  });


  test('handles filter selection changes and saves correctly', async () => {
    const gmp = createGmpMock();
    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      store: true,
      router: true,
    });

    const mockFilters = [
      {
        id: 'alert-filter-uuid',
        name: 'Alert Filter',
        filter_type: 'alert',
        identifier: () => 'Alert Filter (alert-filter-uuid)',
      },
      {
        id: 'alert-filter-uuid-2',
        name: 'Alert Filter 2',
        filter_type: 'alert',
        identifier: () => 'Alert Filter 2 (alert-filter-uuid-2)',
      },
      {
        id: 'credential-filter-uuid',
        name: 'Credential Filter',
        filter_type: 'credential',
        identifier: () => 'Credential Filter (credential-filter-uuid)',
      },
      {
        id: 'credential-filter-uuid-2',
        name: 'Credential Filter 2',
        filter_type: 'credential',
        identifier: () => 'Credential Filter 2 (credential-filter-uuid-2)',
      },
    ];

    store.dispatch({
      type: 'ENTITIES_FILTERS_LOADING_SUCCESS',
      data: mockFilters,
    });

    store.dispatch({
      type: USER_SETTINGS_DEFAULT_FILTER_LOADING_SUCCESS,
      entityType: 'alert',
      filter: mockFilters[0],
    });
    store.dispatch({
      type: USER_SETTINGS_DEFAULT_FILTER_LOADING_SUCCESS,
      entityType: 'credential',
      filter: mockFilters[2],
    });

    render(<FilterSettings />);
    await wait();

    const alertsHeader = screen.getByText('Alerts Filter');
    const alertsRow = alertsHeader.closest('tr') as HTMLTableRowElement;

    fireEvent.click(within(alertsRow).getByRole('button', {name: /edit/i}));
    await wait();

    const alertsSelect = within(alertsRow).getByTestId('form-select');
    (alertsSelect as HTMLInputElement).value = 'alert-filter-uuid-2';
    fireEvent.change(alertsSelect, {target: {value: 'alert-filter-uuid-2'}});
    await wait();

    fireEvent.click(within(alertsRow).getByRole('button', {name: /save/i}));
    await wait();

    store.dispatch({
      type: USER_SETTINGS_DEFAULT_FILTER_LOADING_SUCCESS,
      entityType: 'alert',
      filter: mockFilters[1],
    });
    await wait();

    expect(
      within(alertsRow).getByRole('link', {name: 'alert Filter'}),
    ).toHaveAttribute('href', '/filter/alert-filter-uuid-2');

    const credsHeader = screen.getByText('Credentials Filter');
    const credsRow = credsHeader.closest('tr') as HTMLTableRowElement;

    fireEvent.click(within(credsRow).getByRole('button', {name: /edit/i}));
    await wait();

    const credsSelect = within(credsRow).getByTestId('form-select');
    (credsSelect as HTMLInputElement).value = 'credential-filter-uuid-2';
    fireEvent.change(credsSelect, {
      target: {value: 'credential-filter-uuid-2'},
    });
    await wait();

    fireEvent.click(within(credsRow).getByRole('button', {name: /save/i}));
    await wait();

    store.dispatch({
      type: USER_SETTINGS_DEFAULT_FILTER_LOADING_SUCCESS,
      entityType: 'credential',
      filter: mockFilters[3],
    });
    await wait();

    expect(
      within(credsRow).getByRole('link', {name: 'credential Filter'}),
    ).toHaveAttribute('href', '/filter/credential-filter-uuid-2');
  });
});

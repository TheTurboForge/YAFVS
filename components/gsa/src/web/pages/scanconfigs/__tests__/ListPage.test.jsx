/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  screen,
  testBulkTrashcanDialog,
  rendererWith,
  fireEvent,
  wait,
} from 'web/testing';
import Capabilities from 'gmp/capabilities/capabilities';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import ScanConfig, {
  SCANCONFIG_TREND_STATIC,
  SCANCONFIG_TREND_DYNAMIC,
} from 'gmp/models/scan-config';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import ScanConfigsPage, {ToolBarIcons} from 'web/pages/scanconfigs/ListPage';
import {entitiesLoadingActions} from 'web/store/entities/scanconfigs';
import {defaultFilterLoadingActions} from 'web/store/usersettings/defaultfilters/actions';
import {loadingActions} from 'web/store/usersettings/defaults/actions';

const config = ScanConfig.fromElement({
  _id: '12345',
  name: 'foo',
  comment: 'bar',
  creation_time: '2019-07-16T06:31:29Z',
  modification_time: '2019-07-16T06:44:55Z',
  owner: {name: 'admin'},
  writable: '1',
  in_use: '0',
  usage_type: 'scan',
  permissions: {permission: [{name: 'everything'}]},
  scanner: {name: 'scanner', type: '42'},
  tasks: {
    task: [
      {id: '1234', name: 'task1'},
      {id: '5678', name: 'task2'},
    ],
  },
  family_count: {
    __text: 2,
    growing: SCANCONFIG_TREND_STATIC,
  },
  nvt_count: {
    __text: 4,
    growing: SCANCONFIG_TREND_DYNAMIC,
  },
});

const nativeScanConfigItem = {
  id: '12345',
  name: 'foo',
  comment: 'bar',
  owner: {name: 'admin'},
  family_count: 2,
  families_growing: SCANCONFIG_TREND_STATIC,
  nvt_count: 4,
  nvts_growing: SCANCONFIG_TREND_DYNAMIC,
  predefined: false,
  deprecated: false,
  writable: true,
  in_use: false,
  usage_type: 'scan',
  tasks: [
    {id: '1234', name: 'task1'},
    {id: '5678', name: 'task2'},
  ],
  created_at: '2019-07-16T06:31:29Z',
  modified_at: '2019-07-16T06:44:55Z',
};

const wrongCaps = new Capabilities(['get_config']);

const reloadInterval = 1;
const manualUrl = 'test/';

const createGmp = ({
  buildUrl,
  nativeScanConfigItems = [nativeScanConfigItem],
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  getSetting = testing.fn().mockResolvedValue({filter: null}),
  getConfigs = testing.fn().mockResolvedValue({
    data: [config],
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
  deleteByFilter = testing.fn().mockResolvedValue({
    foo: 'bar',
  }),
  exportByFilter = testing.fn().mockResolvedValue({
    foo: 'bar',
  }),
} = {}) => {
  const resolvedBuildUrl =
    buildUrl ?? testing.fn((path, _params) => `https://yafvs.example/${path}`);
  if (buildUrl === undefined) {
    testing.stubGlobal(
      'fetch',
      testing.fn(url => {
        const path = String(url);
        const payload = path.includes('/api/v1/filters')
          ? {
              page: {
                page: 1,
                page_size: 10,
                total: 0,
                sort: 'name',
                filter: '',
              },
              items: [],
            }
          : {
              page: {
                page: 1,
                page_size: 10,
                total: nativeScanConfigItems.length,
                sort: 'name',
                filter: '',
              },
              items: nativeScanConfigItems,
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
    scanconfigs: {
      get: getConfigs,
      deleteByFilter,
      exportByFilter,
    },
    filters: {
      get: getFilters,
    },
    reloadInterval,
    settings: {
      manualUrl,
    },
    session: {
      ...createSession(),
      token: 'test-token',
      jwt: 'jwt-token',
    },
    user: {currentSettings, getSetting: getSetting},
  };
};

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ScanConfigsPage tests', () => {
  test('should render full ScanConfigsPage', async () => {
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
      defaultFilterLoadingActions.success('scanconfig', defaultSettingFilter),
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
      entitiesLoadingActions.success([config], filter, loadedFilter, counts),
    );

    const {baseElement} = render(
      <ScanConfigsPage openEditNvtDetailsDialog={testing.fn()} />,
    );

    await wait();

    expect(baseElement).toBeInTheDocument();
    expect(screen.queryTable()).toBeInTheDocument();
  });

  test('should call commands for bulk actions', async () => {
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
      defaultFilterLoadingActions.success('scanconfig', defaultSettingFilter),
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
      entitiesLoadingActions.success([config], filter, loadedFilter, counts),
    );

    render(<ScanConfigsPage openEditNvtDetailsDialog={testing.fn()} />);

    await wait();

    const deleteIcon = screen.getAllByTitle(
      'Move page contents to trashcan',
    )[0];
    fireEvent.click(deleteIcon);
    testBulkTrashcanDialog(screen, gmp.scanconfigs.deleteByFilter);

    const exportIcon = screen.getAllByTitle('Export page contents')[0];
    fireEvent.click(exportIcon);
    expect(gmp.scanconfigs.exportByFilter).toHaveBeenCalled();
  });
});

describe('ScanConfigsPage ToolBarIcons test', () => {
  test('should render', () => {
    const handleScanConfigCreateClick = testing.fn();
    const handleScanConfigImportClick = testing.fn();

    const gmp = {
      settings: {manualUrl},
    };

    const {render} = rendererWith({
      gmp,
      capabilities: true,
      router: true,
    });

    const {element} = render(
      <ToolBarIcons
        onScanConfigCreateClick={handleScanConfigCreateClick}
        onScanConfigImportClick={handleScanConfigImportClick}
      />,
    );
    expect(element).toBeVisible();

    const helpIcon = screen.getByTestId('help-icon');
    const links = element.querySelectorAll('a');

    expect(helpIcon).toHaveAttribute('title', 'Help: Scan Configs');
    expect(links[0]).toHaveAttribute(
      'href',
      'test/en/scanning.html#managing-scan-configurations',
    );
  });

  test('should call click handlers', () => {
    const handleScanConfigCreateClick = testing.fn();
    const handleScanConfigImportClick = testing.fn();

    const gmp = {
      settings: {manualUrl},
    };

    const {render} = rendererWith({
      gmp,
      capabilities: true,
      router: true,
    });

    render(
      <ToolBarIcons
        onScanConfigCreateClick={handleScanConfigCreateClick}
        onScanConfigImportClick={handleScanConfigImportClick}
      />,
    );

    const newIcon = screen.getByTestId('new-icon');
    fireEvent.click(newIcon);
    expect(handleScanConfigCreateClick).toHaveBeenCalled();
    expect(newIcon).toHaveAttribute('title', 'New Scan Config');

    const uploadIcon = screen.getByTestId('upload-icon');
    fireEvent.click(uploadIcon);
    expect(handleScanConfigImportClick).toHaveBeenCalled();
    expect(uploadIcon).toHaveAttribute('title', 'Import Scan Config');
  });

  test('should not show icons if user does not have the right permissions', () => {
    const handleScanConfigCreateClick = testing.fn();
    const handleScanConfigImportClick = testing.fn();

    const gmp = {settings: {manualUrl}};

    const {render} = rendererWith({
      gmp,
      capabilities: wrongCaps,
      router: true,
    });

    render(
      <ToolBarIcons
        onScanConfigCreateClick={handleScanConfigCreateClick}
        onScanConfigImportClick={handleScanConfigImportClick}
      />,
    );

    const newIcon = screen.queryByTestId('new-icon');
    expect(newIcon).toBeNull();
    const uploadIcon = screen.queryByTestId('upload-icon');
    expect(uploadIcon).toBeNull();

    expect(screen.getByTestId('help-icon')).toHaveAttribute(
      'title',
      'Help: Scan Configs',
    );
  });
});

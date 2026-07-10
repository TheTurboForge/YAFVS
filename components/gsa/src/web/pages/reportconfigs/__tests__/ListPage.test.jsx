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
import ReportConfig from 'gmp/models/report-config';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import ReportConfigsPage, {
  ToolBarIcons,
} from 'web/pages/reportconfigs/ListPage';
import {entitiesLoadingActions} from 'web/store/entities/reportconfigs';
import {defaultFilterLoadingActions} from 'web/store/usersettings/defaultfilters/actions';
import {loadingActions} from 'web/store/usersettings/defaults/actions';

const config = ReportConfig.fromElement({
  _id: '12345',
  name: 'foo',
  comment: 'bar',
  creation_time: '2019-07-16T06:31:29Z',
  modification_time: '2019-07-16T06:44:55Z',
  owner: {name: 'admin'},
  writable: '1',
  in_use: '0',
  report_format: {
    _id: '54321',
    name: 'baz',
  },
});

const nativeReportConfigItem = {
  id: '12345',
  name: 'foo',
  comment: 'bar',
  owner: {name: 'admin'},
  report_format: {id: '54321', name: 'baz'},
  writable: true,
  in_use: false,
  created_at: '2019-07-16T06:31:29Z',
  modified_at: '2019-07-16T06:44:55Z',
};

const wrongCaps = new Capabilities(['get_config']);

const reloadInterval = 1;
const manualUrl = 'test/';

const currentSettings = testing
  .fn()
  .mockResolvedValue(currentSettingsDefaultResponse);

const createGmp = ({
  deleteByFilter = testing.fn().mockResolvedValue({
    foo: 'bar',
  }),
  nativeReportConfigItems = [nativeReportConfigItem],
  addTagByFilter = testing.fn().mockResolvedValue({
    foo: 'bar',
  }),
  getSetting = testing.fn().mockResolvedValue({filter: null}),
  getReportConfigs = testing.fn().mockResolvedValue({
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
} = {}) => {
  const buildUrl = testing.fn(
    (path, _params) => `https://turbovas.example/${path}`,
  );
  testing.stubGlobal(
    'fetch',
    testing.fn(url => {
      const payload = String(url).includes('/api/v1/report-configs')
        ? {
            page: {
              page: 1,
              page_size: 10,
              total: nativeReportConfigItems.length,
              sort: 'name',
              filter: '',
            },
            items: nativeReportConfigItems,
          }
        : {
            page: {page: 1, page_size: 10, total: 0, sort: 'name', filter: ''},
            items: [],
          };
      return Promise.resolve({
        json: testing.fn().mockResolvedValue(payload),
        ok: true,
        status: 200,
      });
    }),
  );
  return {
    buildUrl,
    reportconfigs: {
      get: getReportConfigs,
      deleteByFilter,
      addTagByFilter,
    },
    filters: {
      get: getFilters,
    },
    reloadInterval,
    settings: {
      manualUrl,
    },
    session: {...createSession(), token: 'test-token', jwt: 'jwt-token'},
    user: {
      currentSettings,
      getSetting,
    },
  };
};

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ReportConfigsPage tests', () => {
  test('should render full ReportConfigsPage', async () => {
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
      defaultFilterLoadingActions.success('reportconfig', defaultSettingFilter),
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

    const {baseElement} = render(<ReportConfigsPage />);

    await wait();

    expect(baseElement).toBeVisible();
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
      defaultFilterLoadingActions.success('reportconfig', defaultSettingFilter),
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

    render(<ReportConfigsPage />);

    await wait();

    const deleteIcon = screen.getAllByTitle(
      'Move page contents to trashcan',
    )[0];
    fireEvent.click(deleteIcon);
    testBulkTrashcanDialog(screen, gmp.reportconfigs.deleteByFilter);
  });

  describe('ReportConfigsPage ToolBarIcons test', () => {
    test('should render', () => {
      const handleReportConfigCreateClick = testing.fn();
      const gmp = createGmp();

      const {render} = rendererWith({
        gmp,
        capabilities: true,
        router: true,
      });

      const {element} = render(
        <ToolBarIcons
          onReportConfigCreateClick={handleReportConfigCreateClick}
        />,
      );
      expect(element).toBeVisible();

      const links = element.querySelectorAll('a');

      expect(screen.getByTestId('help-icon')).toHaveAttribute(
        'title',
        'Help: Report Configs',
      );
      expect(screen.getByTestId('new-icon')).toHaveAttribute(
        'title',
        'New Report Config',
      );
      expect(links[0]).toHaveAttribute(
        'href',
        'test/en/reports.html#customizing-report-formats-with-report-configurations',
      );
    });

    test('should call click handlers', () => {
      const handleReportConfigCreateClick = testing.fn();

      const gmp = createGmp();

      const {render} = rendererWith({
        gmp,
        capabilities: true,
        router: true,
      });

      render(
        <ToolBarIcons
          onReportConfigCreateClick={handleReportConfigCreateClick}
        />,
      );

      const newIcon = screen.getByTestId('new-icon');
      expect(newIcon).toHaveAttribute('title', 'New Report Config');
      fireEvent.click(newIcon);
      expect(handleReportConfigCreateClick).toHaveBeenCalled();
    });

    test('should not show icons if user does not have the right permissions', () => {
      const handleReportConfigCreateClick = testing.fn();

      const gmp = createGmp();

      const {render} = rendererWith({
        gmp,
        capabilities: wrongCaps,
        router: true,
      });

      render(
        <ToolBarIcons
          onReportConfigCreateClick={handleReportConfigCreateClick}
        />,
      );

      const newIcon = screen.queryByTestId('new-icon');
      expect(newIcon).toBeNull();
    });
  });
});

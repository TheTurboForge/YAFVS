/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  screen,
  testBulkTrashcanDialog,
  within,
  rendererWith,
  fireEvent,
  wait,
} from 'web/testing';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import Task, {TASK_STATUS} from 'gmp/models/task';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import TaskListPage from 'web/pages/tasks/TaskListPage';
import {entitiesLoadingActions} from 'web/store/entities/tasks';
import {defaultFilterLoadingActions} from 'web/store/usersettings/defaultfilters/actions';
import {loadingActions} from 'web/store/usersettings/defaults/actions';

const lastReport = {
  report: {
    _id: '1234',
    timestamp: '2019-08-10T12:51:27Z',
    severity: 5.0,
  },
};

const task = Task.fromElement({
  _id: '1234',
  owner: {name: 'admin'},
  name: 'foo',
  comment: 'bar',
  status: TASK_STATUS.done,
  alterable: 0,
  last_report: lastReport,
  report_count: {__text: 1},
  permissions: {permission: [{name: 'everything'}]},
  target: {_id: 'id1', name: 'target1'},
});

const nativeTaskItem = {
  id: '1234',
  name: 'foo',
  comment: 'bar',
  status: 'Done',
  progress: 100,
  trend: '',
  target: {id: 'id1', name: 'target1'},
  report_count: {total: 1, finished: 1},
  last_report: {
    id: '1234',
    timestamp: '2019-08-10T12:51:27Z',
    severity: 5.0,
  },
};

const reloadInterval = 1;
const manualUrl = 'test/';

const createGmp = ({
  exportTask = testing.fn(),
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  getFilters = testing.fn().mockResolvedValue({
    data: [],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
  nativeTaskItems = [nativeTaskItem],
  getUserSetting = testing.fn().mockResolvedValue({
    filter: null,
  }),
  getAggregates = testing.fn().mockResolvedValue({
    data: [],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
  getTasks = testing.fn().mockResolvedValue({
    data: [task],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
  getReportFormats = testing.fn().mockResolvedValue({
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
  const buildUrl = testing.fn(
    (path: string) => `https://yafvs.example/${path}`,
  );
  testing.stubGlobal(
    'fetch',
    testing.fn(url => {
      const payload = String(url).includes('/api/v1/tasks')
        ? {
            page: {
              page: 1,
              page_size: 10,
              total: nativeTaskItems.length,
              sort: 'name',
              filter: '',
            },
            items: nativeTaskItems,
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
    task: {
      export: exportTask,
    },
    tasks: {
      get: getTasks,
      getSeverityAggregates: getAggregates,
      getHighResultsAggregates: getAggregates,
      getStatusAggregates: getAggregates,
      deleteByFilter,
      exportByFilter,
    },
    filters: {
      get: getFilters,
    },
    reportformats: {
      get: getReportFormats,
    },
    reloadInterval,
    settings: {
      manualUrl,
    },
    session: {
      ...createSession({timezone: 'CET'}),
      token: 'test-token',
      jwt: 'jwt-token',
    },
    user: {currentSettings, getSetting: getUserSetting},
  };
};

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('TaskListPage tests', () => {
  test('should render full page', async () => {
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
      defaultFilterLoadingActions.success('task', defaultSettingFilter),
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
      entitiesLoadingActions.success([task], filter, loadedFilter, counts),
    );

    render(<TaskListPage />);

    await wait();

    const powerFilter = within(screen.getPowerFilter());
    const select = powerFilter.getByTestId('powerfilter-select');

    // Toolbar Icons
    const helpIcon = screen.getByTestId('help-icon');
    expect(helpIcon).toHaveAttribute('title', 'Help: Tasks');

    // Powerfilter
    expect(screen.getByTestId('powerfilter-text')).toHaveAttribute(
      'name',
      'userFilterString',
    );
    expect(screen.getByTestId('powerfilter-refresh')).toHaveAttribute(
      'title',
      'Update Filter',
    );
    expect(screen.getByTestId('powerfilter-delete')).toHaveAttribute(
      'title',
      'Remove Filter',
    );
    expect(screen.getByTestId('powerfilter-reset')).toHaveAttribute(
      'title',
      'Reset to Default Filter',
    );
    expect(screen.getByTestId('powerfilter-help')).toHaveAttribute(
      'title',
      'Help: Powerfilter',
    );
    expect(screen.getByTestId('powerfilter-edit')).toHaveAttribute(
      'title',
      'Edit Filter',
    );
    expect(select).toHaveAttribute('title', 'Loaded filter');
    expect(select).toHaveValue('--');

    // Table
    const table = screen.getByTestId('entities-table');
    const header = within(table).getAllByRole('columnheader');
    expect(header[0]).toHaveTextContent('Name');
    expect(header[1]).toHaveTextContent('Status');
    expect(header[2]).toHaveTextContent('Reports');
    expect(header[3]).toHaveTextContent('Last Report');
    expect(header[4]).toHaveTextContent('Severity');
    expect(header[5]).toHaveTextContent('Trend');
    expect(header[6]).toHaveTextContent('Actions');

    const rows = table.querySelectorAll<HTMLElement>('tbody tr');
    const row = rows[0];
    expect(row).toHaveTextContent('foo');
    expect(row).toHaveTextContent('(bar)');
    expect(row).toHaveTextContent('Done');
    expect(row).toHaveTextContent(
      'Sat, Aug 10, 2019 2:51 PM Central European Summer Time',
    );
    expect(row).toHaveTextContent('5.0 (Medium)');

    const withinRow = within(row);
    const startIcon = withinRow.getByTestId('start-icon');
    expect(startIcon).toHaveAttribute('title', 'Start');
    const trashcanIcon = withinRow.getByTestId('trashcan-icon');
    expect(trashcanIcon).toHaveAttribute('title', 'Move Task to trashcan');
    const editIcon = withinRow.getByTestId('edit-icon');
    expect(editIcon).toHaveAttribute('title', 'Edit Task');
    const cloneIcon = withinRow.getByTestId('clone-icon');
    expect(cloneIcon).toHaveAttribute('title', 'Clone Task');
    const exportIcon = withinRow.getByTestId('export-icon');
    expect(exportIcon).toHaveAttribute('title', 'Export Task');
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
      defaultFilterLoadingActions.success('task', defaultSettingFilter),
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
      entitiesLoadingActions.success([task], filter, loadedFilter, counts),
    );

    render(<TaskListPage />);

    await wait();

    // export page contents
    const exportIcon = screen.getByTitle('Export page contents');
    fireEvent.click(exportIcon);
    expect(gmp.tasks.exportByFilter).toHaveBeenCalled();

    // move page contents to trashcan
    const deleteIcon = screen.getByTitle('Move page contents to trashcan');
    fireEvent.click(deleteIcon);
    testBulkTrashcanDialog(screen, gmp.tasks.deleteByFilter);
  });
});

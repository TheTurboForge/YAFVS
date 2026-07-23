/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  getSelectItemElementsForSelect,
  screen,
  testBulkDeleteDialog,
  within,
  rendererWith,
  fireEvent,
  wait,
} from 'web/testing';
import Capabilities from 'gmp/capabilities/capabilities';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import Host from 'gmp/models/host';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import HostPage, {ToolBarIcons} from 'web/pages/hosts/ListPage';
import {entitiesLoadingActions} from 'web/store/entities/hosts';
import {defaultFilterLoadingActions} from 'web/store/usersettings/defaultfilters/actions';
import {loadingActions} from 'web/store/usersettings/defaults/actions';

const wrongCapabilities = new Capabilities(['get_host']);

const reloadInterval = -1;
const manualUrl = 'test/';

// mock entity

const host = Host.fromElement({
  _id: '1234',
  name: 'Foo',
  comment: 'bar',
  owner: {name: 'admin'},
  creation_time: '2019-06-02T12:00:22Z',
  modification_time: '2019-06-03T11:00:22Z',
  writable: '1',
  in_use: '0',
  permissions: {permission: [{name: 'everything'}]},
  host: {
    severity: {
      value: 10.0,
    },
  },
  identifiers: {
    identifier: [
      {
        _id: '5678',
        name: 'hostname',
        value: 'foo',
        source: {
          _id: '910',
          type: 'Report Host Detail',
        },
      },
      {
        _id: '1112',
        name: 'ip',
        value: '123.456.789.10',
      },
      {
        _id: '1314',
        name: 'OS',
        value: 'cpe:/o:linux:kernel',
      },
    ],
  },
});

const nativeHostItem = {
  id: '1234',
  name: 'Foo',
  comment: 'bar',
  hostname: 'foo',
  ip: '123.456.789.10',
  best_os_cpe: 'cpe:/o:linux:kernel',
  severity: 10.0,
  identifiers: [
    {
      id: '5678',
      name: 'hostname',
      value: 'foo',
      source_type: 'Report Host Detail',
      source_id: '910',
    },
    {
      id: '1112',
      name: 'ip',
      value: '123.456.789.10',
    },
    {
      id: '1314',
      name: 'OS',
      value: 'cpe:/o:linux:kernel',
    },
  ],
  created_at: '2019-06-02T12:00:22Z',
  modified_at: '2019-06-03T11:00:22Z',
};

const createGmp = ({
  buildUrl,
  nativeHostItems = [nativeHostItem],
  getHosts = testing.fn().mockResolvedValue({
    data: [host],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
  getFilters = testing.fn().mockReturnValue(
    Promise.resolve({
      data: [],
      meta: {
        filter: Filter.fromString(),
        counts: new CollectionCounts(),
      },
    }),
  ),
  getAggregates = testing.fn().mockResolvedValue({
    data: [],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
  getSetting = testing.fn().mockResolvedValue({
    filter: null,
  }),
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  deleteByFilter = testing.fn().mockResolvedValue({
    foo: 'bar',
  }),
  exportByFilter = testing.fn().mockResolvedValue({
    foo: 'bar',
  }),
  deleteByIds = testing.fn().mockResolvedValue({
    foo: 'bar',
  }),
  exportByIds = testing.fn().mockResolvedValue({
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
                total: nativeHostItems.length,
                sort: '-severity',
                filter: '',
              },
              items: nativeHostItems,
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
    hosts: {
      get: getHosts,
      getSeverityAggregates: getAggregates,
      getModifiedAggregates: getAggregates,
      deleteByFilter,
      exportByFilter,
      delete: deleteByIds,
      export: exportByIds,
    },
    filters: {
      get: getFilters,
    },
    settings: {
      manualUrl,
      reloadInterval,
    },
    session: {
      ...createSession({timezone: 'CET'}),
      token: 'test-token',
      jwt: 'jwt-token',
    },
    user: {currentSettings},
  };
};

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('Host ListPage tests', () => {
  test('should render full host ListPage', async () => {
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
      defaultFilterLoadingActions.success('host', defaultSettingFilter),
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
      entitiesLoadingActions.success([host], filter, loadedFilter, counts),
    );

    const {baseElement} = render(<HostPage />);

    await wait();

    const powerFilter = within(screen.getPowerFilter());
    const select = powerFilter.getByTestId('powerfilter-select');
    const inputs = powerFilter.queryTextInputs();

    // Toolbar Icons
    expect(screen.getAllByTitle('Help: Hosts')[0]).toBeInTheDocument();
    expect(screen.getAllByTitle('New Host')[0]).toBeInTheDocument();

    // Powerfilter
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

    // Table
    const header = baseElement.querySelectorAll('th');

    expect(header[0]).toHaveTextContent('Name');
    expect(header[1]).toHaveTextContent('Hostname');
    expect(header[2]).toHaveTextContent('IP Address');
    expect(header[3]).toHaveTextContent('OS');
    expect(header[4]).toHaveTextContent('Severity');
    expect(header[5]).toHaveTextContent('Modified');
    expect(header[6]).toHaveTextContent('Actions');

    // Row
    const row = baseElement.querySelectorAll('tr');

    expect(row[1]).toHaveTextContent('Foo');
    expect(row[1]).toHaveTextContent('bar');
    expect(row[1]).toHaveTextContent('foo');
    expect(row[1]).toHaveTextContent('123.456.789.10');
    expect(row[1]).toHaveTextContent('10.0 (Critical)');
    expect(row[1]).toHaveTextContent(
      'Mon, Jun 3, 2019 1:00 PM Central European Summer Time',
    );

    const osImage = baseElement.querySelector('img');
    expect(osImage).toHaveAttribute('src', '/img/os_linux.svg');

    expect(screen.getAllByTitle('Delete Host')[0]).toBeInTheDocument();
    expect(screen.getAllByTitle('Edit Host')[0]).toBeInTheDocument();
    expect(
      screen.getAllByTitle('Create Target from Host')[0],
    ).toBeInTheDocument();
    expect(screen.getAllByTitle('Export Host')[0]).toBeInTheDocument();

    // Footer
    expect(
      screen.getAllByTitle('Add tag to page contents')[0],
    ).toBeInTheDocument();
    expect(screen.getAllByTitle('Delete page contents')[0]).toBeInTheDocument();
    expect(screen.getAllByTitle('Export page contents')[0]).toBeInTheDocument();
    expect(
      screen.getAllByTitle('Create Target from page contents')[0],
    ).toBeInTheDocument();
  });

  test('should allow to bulk action on page contents', async () => {
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
      defaultFilterLoadingActions.success('host', defaultSettingFilter),
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
      entitiesLoadingActions.success([host], filter, loadedFilter, counts),
    );

    render(<HostPage />);

    await wait();

    // export page contents
    fireEvent.click(screen.getAllByTitle('Export page contents')[0]);
    await wait();
    expect(gmp.hosts.exportByFilter).toHaveBeenCalled();

    // delete page contents
    fireEvent.click(screen.getAllByTitle('Delete page contents')[0]);
    await wait();
    testBulkDeleteDialog(screen, gmp.hosts.deleteByFilter);
  });

  test('should allow to bulk action on selected hosts', async () => {
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
      defaultFilterLoadingActions.success('host', defaultSettingFilter),
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
      entitiesLoadingActions.success([host], filter, loadedFilter, counts),
    );

    render(<HostPage />);

    await wait();

    // change to apply to selection
    const tableFooter = within(screen.queryTableFooter());
    const select = tableFooter.getSelectElement();
    const selectItems = await getSelectItemElementsForSelect(select);
    fireEvent.click(selectItems[1]);

    // export selected host
    fireEvent.click(screen.getAllByTitle('Export selection')[0]);
    expect(gmp.hosts.export).toHaveBeenCalled();

    // delete selected host
    fireEvent.click(screen.getAllByTitle('Delete selection')[0]);
    testBulkDeleteDialog(screen, gmp.hosts.delete);
  });

  test('should allow to bulk action on filtered hosts', async () => {
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
      defaultFilterLoadingActions.success('host', defaultSettingFilter),
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
      entitiesLoadingActions.success([host], filter, loadedFilter, counts),
    );

    render(<HostPage />);

    await wait();

    // change to all filtered
    const tableFooter = within(screen.queryTableFooter());
    const select = tableFooter.getSelectElement();
    const selectItems = await getSelectItemElementsForSelect(select);
    fireEvent.click(selectItems[2]);
    expect(select).toHaveValue('Apply to all filtered');

    // export all filtered hosts
    fireEvent.click(screen.getAllByTitle('Export all filtered')[0]);
    expect(gmp.hosts.exportByFilter).toHaveBeenCalled();

    fireEvent.click(screen.getAllByTitle('Delete all filtered')[0]);
    testBulkDeleteDialog(screen, gmp.hosts.deleteByFilter);
  });
});

describe('Host ListPage ToolBarIcons test', () => {
  test('should expose native host creation to operators with host read access', () => {
    const handleCreateHostClick = testing.fn();
    const gmp = createGmp();
    const {render} = rendererWith({
      gmp,
      capabilities: new Capabilities(['get_assets']),
      router: true,
    });

    render(<ToolBarIcons onHostCreateClick={handleCreateHostClick} />);

    expect(screen.getByTitle('New Host')).toBeInTheDocument();
  });

  test('should render', () => {
    const handleCreateHostClick = testing.fn();

    const gmp = createGmp();

    const {render} = rendererWith({
      gmp,
      capabilities: true,
      router: true,
    });

    const {element} = render(
      <ToolBarIcons onHostCreateClick={handleCreateHostClick} />,
    );

    const links = element.querySelectorAll('a');

    expect(screen.getByTestId('help-icon')).toHaveAttribute(
      'title',
      'Help: Hosts',
    );
    expect(links[0]).toHaveAttribute(
      'href',
      'test/en/managing-assets.html#managing-hosts',
    );

    expect(screen.getByTestId('new-icon')).toHaveAttribute('title', 'New Host');
  });

  test('should call click handlers', () => {
    const handleCreateHostClick = testing.fn();

    const gmp = createGmp();

    const {render} = rendererWith({
      gmp,
      capabilities: true,
      router: true,
    });

    render(<ToolBarIcons onHostCreateClick={handleCreateHostClick} />);

    fireEvent.click(screen.getAllByTitle('New Host')[0]);
    expect(handleCreateHostClick).toHaveBeenCalled();
  });

  test('should not show icons without host read access', () => {
    const handleCreateHostClick = testing.fn();

    const gmp = createGmp();

    const {render} = rendererWith({
      gmp,
      capabilities: wrongCapabilities,
      router: true,
    });

    render(<ToolBarIcons onHostCreateClick={handleCreateHostClick} />);

    expect(screen.getAllByTitle('Help: Hosts')[0]).toBeInTheDocument();
    expect(screen.queryByTitle('New Host')).not.toBeInTheDocument();
  });
});

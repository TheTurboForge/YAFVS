/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fireEvent, rendererWith, screen} from 'web/testing';

import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import Host from 'gmp/models/host';

import {type ModelElement} from 'gmp/models/model';
import {createSession} from 'gmp/testing';
import {SEVERITY_RATING_CVSS_3} from 'gmp/utils/severity';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import HostsDialog from 'web/pages/hosts/Dialog';
import HostWithTargetComponent from 'web/pages/hosts/HostComponent';

interface SelectionDialogData {
  entities: Array<{id: string}>;
  entitiesSelected: Set<{id: string}>;
  selectionType: string;
  filter: Filter;
}

const host = Host.fromElement({
  _id: '12345',
  name: 'Foo',
  comment: 'bar',
  owner: {name: 'admin'},
  creation_time: '2019-06-02T12:00:22Z',
  modification_time: '2019-06-03T11:00:22Z',
  writable: 1,
  in_use: 0,
  permissions: {permission: [{name: 'everything'}]},
  host: {
    severity: {
      value: 10.0,
    },
    detail: [
      {
        name: 'best_os_cpe',
        value: 'cpe:/o:linux:kernel',
        source: {
          _id: '910',
          type: 'Report',
        },
      },
      {
        name: 'best_os_txt',
        value: 'Linux/Unix',
        source: {
          _id: '910',
          type: 'Report',
        },
      },
      {
        name: 'traceroute',
        value: '123.456.789.10,123.456.789.11',
        source: {
          _id: '910',
          type: 'Report',
        },
      },
    ],
    routes: {
      route: [
        {
          host: [
            {
              _id: '10',
              ip: '123.456.789.10',
            },
            {
              _id: '01',
              ip: '123.456.789.11',
            },
          ],
        },
      ],
    },
  },
  identifiers: {
    identifier: [
      {
        _id: '5678',
        name: 'hostname',
        value: 'foo',
        creation_time: '2019-06-02T12:00:22Z',
        modification_time: '2019-06-03T11:00:22Z',
        source: {
          _id: '910',
          type: 'Report Host Detail',
          data: '1.2.3.4.5',
        },
      },
      {
        _id: '1112',
        name: 'ip',
        value: '123.456.789.10',
        creation_time: '2019-06-02T12:00:22Z',
        modification_time: '2019-06-03T11:00:22Z',
        source: {
          _id: '910',
          type: 'Report Host Detail',
          data: '1.2.3.4.5',
        },
      },
      {
        _id: '1314',
        name: 'OS',
        value: 'cpe:/o:linux:kernel',
        creation_time: '2019-06-02T12:00:22Z',
        modification_time: '2019-06-03T11:00:22Z',
        source: {
          _id: '910',
          type: 'Report Host Detail',
          data: '1.2.3.4.5',
        },
        os: {
          _id: '1314',
          title: 'TestOs',
        },
      },
    ],
  },
} as ModelElement) as Host;

const nativeHostPayload = {
  asset: {
    id: '12345',
    name: 'Foo',
    comment: 'bar',
    severity: 10.0,
  },
  identifiers: [],
  operating_systems: [],
  details: [],
};

const createGmp = ({
  buildUrl,
  exportHost = testing.fn().mockResolvedValue({data: '<host id="12345"/>'}),
  getHost = testing.fn().mockResolvedValue({data: host}),
  getPermissions = testing.fn().mockResolvedValue({
    data: [],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  getCredentials = testing.fn().mockResolvedValue({data: []}),
  getPortLists = testing.fn().mockResolvedValue({data: []}),
  getStableTargetSourceIds = testing.fn().mockResolvedValue([]),
  createTarget = testing
    .fn()
    .mockResolvedValue({data: {id: 'created-target-id'}}),
}: {
  buildUrl?: (path: string, params?: unknown) => string;
  exportHost?: ReturnType<typeof testing.fn>;
  getHost?: ReturnType<typeof testing.fn>;
  getPermissions?: ReturnType<typeof testing.fn>;
  currentSettings?: ReturnType<typeof testing.fn>;
  getCredentials?: ReturnType<typeof testing.fn>;
  getPortLists?: ReturnType<typeof testing.fn>;
  getStableTargetSourceIds?: ReturnType<typeof testing.fn>;
  createTarget?: ReturnType<typeof testing.fn>;
} = {}) => ({
  buildUrl,
  host: {export: exportHost, get: getHost},
  hosts: {getStableTargetSourceIds},
  target: {create: createTarget},
  permissions: {get: getPermissions},
  credentials: {
    getAll: getCredentials,
  },
  portlists: {
    getAll: getPortLists,
  },
  user: {currentSettings},
  settings: {
    manualUrl: 'test/',
    reloadInterval: -1,
    severityRating: SEVERITY_RATING_CVSS_3,
  },
  session: {...createSession(), token: 'test-token', jwt: 'jwt-token'},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('HostWithTargetComponent tests', () => {
  test('should use native metadata export for downloads', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue(nativeHostPayload),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const exportHost = testing.fn().mockResolvedValue({data: '<host/>'});
    const buildUrl = testing.fn(
      (path: string, _params: unknown) => `https://yafvs.example/${path}`,
    );
    const gmp = createGmp({buildUrl, exportHost});
    let downloadClick: (host: Host) => void = () => {};
    const onDownloaded = testing.fn();
    const onDownloadError = testing.fn();

    rendererWith({gmp, capabilities: true}).render(
      <HostWithTargetComponent
        onDownloadError={onDownloadError}
        onDownloaded={onDownloaded}
        onTargetCreateError={testing.fn()}
        onTargetCreated={testing.fn()}
      >
        {({download}) => {
          downloadClick = download;
          return <div data-testid="child">Ready</div>;
        }}
      </HostWithTargetComponent>,
    );

    await screen.findByTestId('child');
    downloadClick(host);
    await expect.poll(() => fetchMock.mock.calls.length).toBe(1);

    expect(exportHost).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith('api/v1/hosts/12345/export', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      'https://yafvs.example/api/v1/hosts/12345/export',
      expect.objectContaining({credentials: 'include'}),
    );
    expect(onDownloaded).toHaveBeenCalledWith({
      filename: 'host-12345.json',
      data: `${JSON.stringify(nativeHostPayload, null, 2)}\n`,
    });
    expect(onDownloadError).not.toHaveBeenCalled();
  });

  test('should call onInteraction and display HostDialog when edit is triggered', () => {
    const gmp = createGmp();
    const onTargetCreated = testing.fn();
    const onTargetCreateError = testing.fn();
    const handleClose = testing.fn();
    const handleSave = testing.fn();

    let editFn: (host: {id: string; name: string}) => void = () => {};

    rendererWith({gmp, capabilities: true}).render(
      <HostWithTargetComponent
        onTargetCreateError={onTargetCreateError}
        onTargetCreated={onTargetCreated}
      >
        {({edit}) => {
          editFn = edit;
          return <HostsDialog onClose={handleClose} onSave={handleSave} />;
        }}
      </HostWithTargetComponent>,
    );

    editFn({id: 'host-123', name: 'Test Host'});

    expect(screen.getDialog()).toBeInTheDocument();
  });

  test('should create a native target from the selected host ID', async () => {
    const createTarget = testing
      .fn()
      .mockResolvedValue({data: {id: 'created-target-id'}});
    const gmp = createGmp({createTarget});

    let triggerFn: (host: Host) => void = () => {};

    rendererWith({gmp, capabilities: true}).render(
      <HostWithTargetComponent
        onTargetCreateError={testing.fn()}
        onTargetCreated={testing.fn()}
      >
        {({createtargetfromhost}) => {
          triggerFn = createtargetfromhost;
          return <div data-testid="child">Ready</div>;
        }}
      </HostWithTargetComponent>,
    );

    await screen.findByTestId('child');

    triggerFn(host);
    await expect.poll(() => screen.getDialog()).toBeInTheDocument();
    fireEvent.click(screen.getDialogSaveButton());
    await expect
      .poll(() => createTarget)
      .toHaveBeenCalledWith(
        expect.objectContaining({
          targetSource: 'asset_hosts',
          hostsCount: 1,
          hostAssetIds: ['12345'],
        }),
      );
  });

  test('should hold the target-source lock through dialog preparation', async () => {
    let triggerSelectionDialog: (
      data: SelectionDialogData,
    ) => Promise<void> = async () => {};
    let resolveCredentials: (value: {data: []}) => void = () => {};
    const getCredentials = testing.fn(
      () =>
        new Promise<{data: []}>(resolve => {
          resolveCredentials = resolve;
        }),
    );
    const getStableTargetSourceIds = testing
      .fn()
      .mockResolvedValue(['h1', 'h2']);
    const gmp = createGmp({getCredentials, getStableTargetSourceIds});
    const filter = Filter.fromString('rows=-1 search=web');

    rendererWith({gmp, capabilities: true}).render(
      <HostWithTargetComponent
        onTargetCreateError={testing.fn()}
        onTargetCreated={testing.fn()}
      >
        {({createtargetfromselection}) => {
          triggerSelectionDialog = createtargetfromselection;
          return <div data-testid="child">Test</div>;
        }}
      </HostWithTargetComponent>,
    );

    const data = {
      entities: [],
      entitiesSelected: new Set<{id: string}>(),
      filter,
      selectionType: '2',
    };
    const first = triggerSelectionDialog(data);
    const competing = triggerSelectionDialog(data);
    await competing;

    expect(getStableTargetSourceIds).toHaveBeenCalledTimes(1);
    expect(getCredentials).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    resolveCredentials({data: []});
    await first;
    await expect.poll(() => screen.getDialog()).toBeInTheDocument();
  });

  test('should snapshot the current page host IDs', async () => {
    let triggerSelectionDialog: (
      data: SelectionDialogData,
    ) => Promise<void> = async () => {};
    const createTarget = testing
      .fn()
      .mockResolvedValue({data: {id: 'created-target-id'}});
    const gmp = createGmp({createTarget});

    rendererWith({gmp, capabilities: true}).render(
      <HostWithTargetComponent
        onTargetCreateError={testing.fn()}
        onTargetCreated={testing.fn()}
      >
        {({createtargetfromselection}) => {
          triggerSelectionDialog = createtargetfromselection;
          return <div data-testid="child">Test</div>;
        }}
      </HostWithTargetComponent>,
    );

    await triggerSelectionDialog({
      entities: [{id: 'h1'}, {id: 'h2'}],
      entitiesSelected: new Set<{id: string}>(),
      filter: Filter.fromString('severity>7'),
      selectionType: '0',
    });

    await expect.poll(() => screen.getDialog()).toBeInTheDocument();
    fireEvent.click(screen.getDialogSaveButton());
    await expect
      .poll(() => createTarget)
      .toHaveBeenCalledWith(
        expect.objectContaining({
          targetSource: 'asset_hosts',
          hostsCount: 2,
          hostAssetIds: ['h1', 'h2'],
        }),
      );
  });

  test('should preserve and deduplicate explicitly selected host IDs', async () => {
    let triggerSelectionDialog: (
      data: SelectionDialogData,
    ) => Promise<void> = async () => {};
    const createTarget = testing
      .fn()
      .mockResolvedValue({data: {id: 'created-target-id'}});
    const gmp = createGmp({createTarget});

    rendererWith({gmp, capabilities: true}).render(
      <HostWithTargetComponent
        onTargetCreateError={testing.fn()}
        onTargetCreated={testing.fn()}
      >
        {({createtargetfromselection}) => {
          triggerSelectionDialog = createtargetfromselection;
          return <div data-testid="child">Test</div>;
        }}
      </HostWithTargetComponent>,
    );

    const selectedHosts = new Set([{id: 'h1'}, {id: 'h2'}, {id: 'h1'}]);

    await triggerSelectionDialog({
      entities: [],
      entitiesSelected: selectedHosts,
      filter: Filter.fromString('search=ignored'),
      selectionType: '1',
    });

    await expect.poll(() => screen.getDialog()).toBeInTheDocument();
    fireEvent.click(screen.getDialogSaveButton());
    await expect
      .poll(() => createTarget)
      .toHaveBeenCalledWith(
        expect.objectContaining({
          targetSource: 'asset_hosts',
          hostsCount: 2,
          hostAssetIds: ['h1', 'h2'],
        }),
      );
  });

  test('should stabilize all filtered host IDs before opening the dialog', async () => {
    let triggerSelectionDialog: (
      data: SelectionDialogData,
    ) => Promise<void> = async () => {};
    const filter = Filter.fromString('rows=-1 search=web');
    const getStableTargetSourceIds = testing
      .fn()
      .mockResolvedValue(['h1', 'h2']);
    const createTarget = testing
      .fn()
      .mockResolvedValue({data: {id: 'created-target-id'}});
    const gmp = createGmp({createTarget, getStableTargetSourceIds});

    rendererWith({gmp, capabilities: true}).render(
      <HostWithTargetComponent
        onTargetCreateError={testing.fn()}
        onTargetCreated={testing.fn()}
      >
        {({createtargetfromselection}) => {
          triggerSelectionDialog = createtargetfromselection;
          return <div data-testid="child">Test</div>;
        }}
      </HostWithTargetComponent>,
    );

    await triggerSelectionDialog({
      entities: [],
      entitiesSelected: new Set(),
      filter,
      selectionType: '2',
    });

    expect(getStableTargetSourceIds).toHaveBeenCalledWith(filter);
    await expect.poll(() => screen.getDialog()).toBeInTheDocument();
    fireEvent.click(screen.getDialogSaveButton());
    await expect
      .poll(() => createTarget)
      .toHaveBeenCalledWith(
        expect.objectContaining({
          targetSource: 'asset_hosts',
          hostsCount: 2,
          hostAssetIds: ['h1', 'h2'],
        }),
      );
  });

  test('should report all-filtered preflight failure without opening a dialog', async () => {
    let triggerSelectionDialog: (
      data: SelectionDialogData,
    ) => Promise<void> = async () => {};
    const failure = new Error('candidate-set drift');
    const getStableTargetSourceIds = testing.fn().mockRejectedValue(failure);
    const onTargetCreateError = testing.fn();
    const gmp = createGmp({getStableTargetSourceIds});

    rendererWith({gmp, capabilities: true}).render(
      <HostWithTargetComponent
        onTargetCreateError={onTargetCreateError}
        onTargetCreated={testing.fn()}
      >
        {({createtargetfromselection}) => {
          triggerSelectionDialog = createtargetfromselection;
          return <div data-testid="child">Test</div>;
        }}
      </HostWithTargetComponent>,
    );

    await triggerSelectionDialog({
      entities: [],
      entitiesSelected: new Set(),
      filter: Filter.fromString('rows=-1'),
      selectionType: '2',
    });

    expect(onTargetCreateError).toHaveBeenCalledWith(failure);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});

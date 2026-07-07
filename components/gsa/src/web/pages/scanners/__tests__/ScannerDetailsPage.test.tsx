/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {rendererWith, fireEvent, screen, wait} from 'web/testing';
import Features from 'gmp/capabilities/features';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import Scanner, {OPENVAS_SCANNER_TYPE} from 'gmp/models/scanner';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import ScannerDetailsPage from 'web/pages/scanners/ScannerDetailsPage';
import {entityLoadingActions} from 'web/store/entities/scanners';

const reloadInterval = -1;
const manualUrl = 'test/';

const createMockScanner = (
  type: string = OPENVAS_SCANNER_TYPE,
) => {
  const baseScanner = {
    _id: 'scanner-123',
    owner: {name: 'admin'},
    name: 'Test Scanner',
    comment: 'Test comment',
    type,
    host: 'localhost',
    port: 9390,
    creation_time: '2024-01-15T10:00:00Z',
    modification_time: '2024-01-16T12:00:00Z',
  };

  return Scanner.fromElement(baseScanner);
};

const createGmp = ({
  buildUrl = undefined,
  scanner = createMockScanner(),
  exportScanner = testing.fn().mockResolvedValue({data: '<scanner/>'}),
  getScanner = testing.fn().mockResolvedValue({data: scanner}),
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  getEntities = testing.fn().mockResolvedValue({
    data: [],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
}: any = {}) => ({
  buildUrl,
  scanner: {
    export: exportScanner,
    get: getScanner,
  },
  permissions: {
    get: getEntities,
  },
  settings: {
    manualUrl,
    reloadInterval,
  },
  session: {
    ...createSession(),
    token: 'test-token',
    jwt: 'jwt-token',
  },
  user: {
    currentSettings,
  },
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('ScannerDetailsPage tests', () => {
  test('should render scanner details page', () => {
    const scanner = createMockScanner();
    const gmp = createGmp({scanner});

    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success('scanner-123', scanner));

    render(<ScannerDetailsPage id="scanner-123" />);

    expect(
      screen.getByRole('heading', {name: /Scanner: Test Scanner/}),
    ).toBeInTheDocument();
    expect(screen.getByText('Test comment')).toBeInTheDocument();
  });

  test('should render information tab', () => {
    const scanner = createMockScanner();
    const gmp = createGmp({scanner});

    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success('scanner-123', scanner));

    render(<ScannerDetailsPage id="scanner-123" />);

    expect(screen.getByRole('tab', {name: 'Information'})).toBeInTheDocument();
  });

  test('should render user tags tab', () => {
    const scanner = createMockScanner();
    const gmp = createGmp({scanner});

    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success('scanner-123', scanner));

    render(<ScannerDetailsPage id="scanner-123" />);

    expect(
      screen.getByRole('tab', {name: 'User Tags ( 0 )'}),
    ).toBeInTheDocument();
  });







  test('should display user tags content when tab is clicked', () => {
    const scanner = createMockScanner();
    const gmp = createGmp({scanner});

    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success('scanner-123', scanner));

    const {container} = render(<ScannerDetailsPage id="scanner-123" />);

    const userTagsTab = screen.getByRole('tab', {name: 'User Tags ( 0 )'});
    fireEvent.click(userTagsTab);

    expect(container).toHaveTextContent('No user tags available');
  });


  test('should render toolbar icons', () => {
    const scanner = createMockScanner();
    const gmp = createGmp({scanner});

    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success('scanner-123', scanner));

    render(<ScannerDetailsPage id="scanner-123" />);

    expect(screen.getByTitle('Help: Scanners')).toBeInTheDocument();
    expect(screen.getByTitle('Scanner List')).toBeInTheDocument();
  });

  test('should use native metadata export for downloads', async () => {
    const scanner = createMockScanner();
    const nativePayload = {
      id: scanner.id,
      name: 'Test Scanner',
      type: OPENVAS_SCANNER_TYPE,
      host: 'localhost',
      port: 9390,
    };
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue(nativePayload),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const exportScanner = testing.fn().mockResolvedValue({data: '<scanner/>'});
    const buildUrl = testing.fn(
      (path, _params) => `https://turbovas.example/${path}`,
    );
    const gmp = createGmp({buildUrl, exportScanner, scanner});

    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success(scanner.id, scanner));
    render(<ScannerDetailsPage id={scanner.id} />);
    await wait();

    fetchMock.mockClear();
    fireEvent.click(screen.getByTitle('Export Scanner as JSON'));
    await expect.poll(() => fetchMock.mock.calls.length).toBe(1);

    expect(exportScanner).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith(
      `api/v1/scanners/${scanner.id}/export`,
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      `https://turbovas.example/api/v1/scanners/${scanner.id}/export`,
      expect.objectContaining({credentials: 'include'}),
    );
  });

});

/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {rendererWith, fireEvent, screen} from 'web/testing';
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
  scanner = createMockScanner(),
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
} = {}) => ({
  scanner: {
    get: getScanner,
  },
  permissions: {
    get: getEntities,
  },
  settings: {
    manualUrl,
    reloadInterval,
  },
  session: createSession(),
  user: {
    currentSettings,
  },
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

});

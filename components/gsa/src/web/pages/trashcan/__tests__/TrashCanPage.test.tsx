/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {screen, rendererWith, waitFor, fireEvent, wait} from 'web/testing';
import Capabilities from 'gmp/capabilities/capabilities';
import {
  NativeTrashcanEmptyIndeterminateError,
  NativeTrashcanEmptyPreviewChangedError,
} from 'gmp/native-api/trashcan';
import TrashcanPage from 'web/pages/trashcan/TrashCanPage';

/*
 * The following is a workaround for userEvent v14 and fake timers https://github.com/testing-library/react-testing-library/issues/1197
 */

testing.useFakeTimers({
  shouldAdvanceTime: true,
});

const gmp = {
  trashcan: {
    empty: testing.fn().mockResolvedValueOnce({}),
    get: testing.fn().mockResolvedValue({
      data: {},
    }),
  },
  settings: {
    manualUrl: 'http://docs.greenbone.net/GSM-Manual/gos-5/',
  },
};

const capabilities = new Capabilities(['everything']);

const EMPTY_PREVIEW_RESOURCE_TYPES = [
  'configs',
  'alerts',
  'credentials',
  'filters',
  'overrides',
  'port_lists',
  'scanners',
  'schedules',
  'tags',
  'targets',
  'tasks',
  'report_formats',
];
const SNAPSHOT_DIGEST = 'a'.repeat(64);

const emptyPreview = (total: number) => ({
  scope: 'operator' as const,
  snapshot_digest: SNAPSHOT_DIGEST,
  items: EMPTY_PREVIEW_RESOURCE_TYPES.map(resource_type => ({
    resource_type,
    count: resource_type === 'targets' ? total : 0,
  })),
  total,
});

const createNativeGmp = ({
  empty = testing.fn().mockResolvedValue({
    scope: 'operator',
    deleted_total: 3,
  }),
  emptyPreviewRequest = testing.fn().mockResolvedValue(emptyPreview(3)),
} = {}) => ({
  buildUrl: testing.fn((path: string) => path),
  session: {token: 'token-1'},
  settings: gmp.settings,
  trashcan: {
    empty,
    emptyPreview: emptyPreviewRequest,
    get: testing.fn().mockResolvedValue({data: {}}),
  },
});

describe('TrashCanPage tests', () => {
  test('previews the operator trashcan count before emptying it once', async () => {
    const empty = testing.fn().mockResolvedValue({
      scope: 'operator',
      deleted_total: 3,
    });
    const emptyPreviewRequest = testing.fn().mockResolvedValue(emptyPreview(3));
    const nativeGmp = createNativeGmp({empty, emptyPreviewRequest});
    const {render} = rendererWith({
      gmp: nativeGmp,
      capabilities,
      store: true,
    });

    render(<TrashcanPage />);

    expect(screen.queryByTestId('loading')).toBeVisible();
    await wait();
    expect(screen.queryByTestId('loading')).not.toBeInTheDocument();
    const emptyTrashcanButton = screen.getByRole('button', {
      name: /Empty Trash/i,
    });

    fireEvent.click(emptyTrashcanButton);
    await waitFor(() => {
      expect(emptyPreviewRequest).toHaveBeenCalledTimes(1);
      expect(screen.getByText('Items: 3')).toBeVisible();
    });
    expect(
      screen.getByText('Are you sure you want to empty the trash?'),
    ).toBeVisible();
    expect(screen.getByText('Scope: operator')).toBeVisible();

    const confirmButton = screen.getByRole('button', {name: /Confirm/i});
    fireEvent.click(confirmButton);
    await waitFor(() => {
      expect(empty).toHaveBeenCalledWith({
        expectedTotal: 3,
        expectedSnapshotDigest: SNAPSHOT_DIGEST,
      });
      expect(empty).toHaveBeenCalledTimes(1);
      expect(confirmButton).not.toBeVisible();
    });
    expect(nativeGmp.trashcan.get).toHaveBeenCalledTimes(2);
  });

  test('submits one native empty request when Confirm is clicked twice while in flight', async () => {
    type EmptyResult = {scope: 'operator'; deleted_total: number};
    let resolveEmpty: (result: EmptyResult) => void = () => {};
    const empty = testing.fn().mockImplementation(
      () =>
        new Promise<EmptyResult>(resolve => {
          resolveEmpty = resolve;
        }),
    );
    const nativeGmp = createNativeGmp({empty});
    const {render} = rendererWith({
      gmp: nativeGmp,
      capabilities,
      store: true,
    });

    render(<TrashcanPage />);
    await wait();
    fireEvent.click(screen.getByRole('button', {name: /Empty Trash/i}));
    await waitFor(() => {
      expect(screen.getByText('Items: 3')).toBeVisible();
    });

    const confirmButton = screen.getByRole('button', {name: /Confirm/i});
    fireEvent.click(confirmButton);
    fireEvent.click(confirmButton);

    await waitFor(() => {
      expect(empty).toHaveBeenCalledTimes(1);
      expect(empty).toHaveBeenCalledWith({
        expectedTotal: 3,
        expectedSnapshotDigest: SNAPSHOT_DIGEST,
      });
    });

    resolveEmpty({scope: 'operator', deleted_total: 3});
    await waitFor(() => {
      expect(confirmButton).not.toBeVisible();
    });
  });

  test('requires reconfirmation after a changed preview', async () => {
    const empty = testing
      .fn()
      .mockRejectedValueOnce(new NativeTrashcanEmptyPreviewChangedError())
      .mockResolvedValueOnce({scope: 'operator', deleted_total: 4});
    const emptyPreviewRequest = testing
      .fn()
      .mockResolvedValueOnce(emptyPreview(3))
      .mockResolvedValueOnce(emptyPreview(4));
    const nativeGmp = createNativeGmp({empty, emptyPreviewRequest});
    const {render} = rendererWith({
      gmp: nativeGmp,
      capabilities,
      store: true,
    });

    render(<TrashcanPage />);
    await wait();
    fireEvent.click(screen.getByRole('button', {name: /Empty Trash/i}));
    await waitFor(() => {
      expect(screen.getByText('Items: 3')).toBeVisible();
    });

    const confirmButton = screen.getByRole('button', {name: /Confirm/i});
    fireEvent.click(confirmButton);
    await waitFor(() => {
      expect(empty).toHaveBeenCalledTimes(1);
      expect(empty).toHaveBeenLastCalledWith({
        expectedTotal: 3,
        expectedSnapshotDigest: SNAPSHOT_DIGEST,
      });
      expect(emptyPreviewRequest).toHaveBeenCalledTimes(2);
      expect(
        screen.getByText(
          'Trashcan contents changed. Review the updated preview and confirm again.',
        ),
      ).toBeVisible();
      expect(screen.getByText('Items: 4')).toBeVisible();
    });

    fireEvent.click(screen.getByRole('button', {name: /Confirm/i}));
    await waitFor(() => {
      expect(empty).toHaveBeenCalledTimes(2);
      expect(empty).toHaveBeenLastCalledWith({
        expectedTotal: 4,
        expectedSnapshotDigest: SNAPSHOT_DIGEST,
      });
    });
  });

  test('does not claim success after an indeterminate empty result', async () => {
    const empty = testing
      .fn()
      .mockRejectedValue(new NativeTrashcanEmptyIndeterminateError());
    const nativeGmp = createNativeGmp({empty});
    const {render} = rendererWith({
      gmp: nativeGmp,
      capabilities,
      store: true,
    });

    render(<TrashcanPage />);
    await wait();
    fireEvent.click(screen.getByRole('button', {name: /Empty Trash/i}));
    await waitFor(() => {
      expect(screen.getByText('Items: 3')).toBeVisible();
    });

    fireEvent.click(screen.getByRole('button', {name: /Confirm/i}));
    await waitFor(() => {
      expect(empty).toHaveBeenCalledTimes(1);
      expect(
        screen.getByText(
          'The result could not be confirmed. Refresh the trashcan and obtain a new preview before trying again.',
        ),
      ).toBeVisible();
    });
    expect(nativeGmp.trashcan.get).toHaveBeenCalledTimes(2);
    expect(screen.getByRole('button', {name: /Refresh/i})).toBeVisible();
  });

  test('Should render open and close dialog', async () => {
    const nativeGmp = createNativeGmp();
    const {render} = rendererWith({
      gmp: nativeGmp,
      capabilities,
      store: true,
    });

    render(<TrashcanPage />);
    expect(screen.queryByTestId('loading')).toBeVisible();
    await wait();
    expect(screen.queryByTestId('loading')).not.toBeInTheDocument();
    const emptyTrashcanButton = screen.getByRole('button', {
      name: /Empty Trash/i,
    });

    fireEvent.click(emptyTrashcanButton);
    await waitFor(() => {
      expect(
        screen.getByText('Are you sure you want to empty the trash?'),
      ).toBeVisible();
    });

    const cancelButton = screen.getByRole('button', {name: /Cancel/i});
    fireEvent.click(cancelButton);
    expect(cancelButton).not.toBeVisible();
  });

  test('Should render native trashcan summary counts when available', async () => {
    const previousFetch = globalThis.fetch;
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      json: testing.fn().mockResolvedValue({
        items: [
          {resource_type: 'credentials', title: 'Credentials', count: 4},
          {resource_type: 'targets', title: 'Targets', count: 1},
        ],
        total: 5,
      }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const nativeGmp = {
      ...gmp,
      buildUrl: testing.fn((path: string) => path),
      session: {token: 'token-1'},
      trashcan: {
        ...gmp.trashcan,
        get: testing.fn().mockResolvedValue({
          data: {
            alerts: [],
            scanConfigs: [],
            credentials: [],
            filters: [],
            overrides: [],
            portLists: [],
            reportFormats: [],
            scanners: [],
            schedules: [],
            tags: [],
            targets: [],
            tasks: [],
          },
        }),
      },
    };
    const {render} = rendererWith({
      gmp: nativeGmp,
      capabilities,
      store: true,
    });

    try {
      render(<TrashcanPage />);
      await wait();

      expect(nativeGmp.buildUrl).toHaveBeenCalledWith(
        'api/v1/trashcan/summary',
        {token: 'token-1'},
      );
      expect(fetchMock).toHaveBeenCalledWith('api/v1/trashcan/summary', {
        credentials: 'include',
        headers: {Accept: 'application/json'},
      });
      expect(screen.getByRole('link', {name: /Credentials/i})).toBeVisible();
      expect(screen.getByText('4')).toBeVisible();
      expect(screen.getByRole('link', {name: /Targets/i})).toBeVisible();
      expect(screen.getByText('1')).toBeVisible();
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
});

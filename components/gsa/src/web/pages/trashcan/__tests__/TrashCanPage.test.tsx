/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {screen, rendererWith, waitFor, fireEvent, wait} from 'web/testing';
import Capabilities from 'gmp/capabilities/capabilities';
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

describe('TrashCanPage tests', () => {
  test('Should render with empty trashcan button and empty out trash', async () => {
    const {render} = rendererWith({
      gmp,
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
    await wait();
    expect(
      screen.getByText('Are you sure you want to empty the trash?'),
    ).toBeVisible();

    const confirmButton = screen.getByRole('button', {name: /Confirm/i});
    fireEvent.click(confirmButton);
    expect(gmp.trashcan.empty).toHaveBeenCalled();

    await wait();

    await waitFor(() => {
      expect(confirmButton).not.toBeVisible();
    });
  });

  test('Should render with empty trashcan button and handle error case', async () => {
    const errorGmp = {
      ...gmp,
      trashcan: {
        ...gmp.trashcan,
        empty: testing
          .fn()
          .mockRejectedValue(new Error('Failed to empty trash')),
      },
    };
    const {render} = rendererWith({
      gmp: errorGmp,
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
    await wait();
    expect(
      screen.getByText('Are you sure you want to empty the trash?'),
    ).toBeVisible();

    const confirmButton = screen.getByRole('button', {name: /Confirm/i});
    fireEvent.click(confirmButton);
    expect(errorGmp.trashcan.empty).toHaveBeenCalled();
    await wait();
    expect(
      screen.getByText(
        'An error occurred while emptying the trash, please try again.',
      ),
    ).toBeVisible();
  });

  test('Should render open and close dialog', async () => {
    const {render} = rendererWith({
      gmp,
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
    expect(
      screen.getByText('Are you sure you want to empty the trash?'),
    ).toBeVisible();

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
            reportConfigs: [],
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

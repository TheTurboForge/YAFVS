/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, expect, test, testing} from '@gsa/testing';
import {settlePortListBulkDelete} from 'web/pages/portlists/PortListListPage';

describe('settlePortListBulkDelete', () => {
  test('refreshes after successful deletion', async () => {
    const refetch = testing.fn();
    const showError = testing.fn();

    await settlePortListBulkDelete(Promise.resolve(), refetch, showError);

    expect(refetch).toHaveBeenCalledOnce();
    expect(showError).not.toHaveBeenCalled();
  });

  test('refreshes and reports a partial deletion failure', async () => {
    const error = new Error('deletion stopped after a committed item');
    const refetch = testing.fn();
    const showError = testing.fn();

    await settlePortListBulkDelete(Promise.reject(error), refetch, showError);

    expect(refetch).toHaveBeenCalledOnce();
    expect(showError).toHaveBeenCalledWith(error);
  });
});

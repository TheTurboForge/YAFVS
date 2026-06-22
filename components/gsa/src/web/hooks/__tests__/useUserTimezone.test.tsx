/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {act, rendererWith, waitFor} from 'web/testing';
import {createSession} from 'gmp/testing';
import useTimezone from 'web/hooks/useUserTimezone';

const createGmp = () => ({
  session: createSession({
    timezone: 'initial-timezone',
  }),
});

describe('useUserTimezone tests', () => {
  test('should return the user timezone', () => {
    const gmp = createGmp();
    const {renderHook} = rendererWith({gmp});

    const {result} = renderHook(() => useTimezone());

    expect(result.current[0]).toBe('initial-timezone');
  });

  test('should allow to update the user timezone', async () => {
    const gmp = createGmp();
    const {renderHook} = rendererWith({gmp});

    const {result} = renderHook(() => useTimezone());
    const [timezone, setTimezone] = result.current;

    expect(timezone).toBe('initial-timezone');

    act(() => {
      setTimezone('updated-timezone');
    });

    await waitFor(() => {
      expect(result.current[0]).toBe('updated-timezone');
    });
  });
});

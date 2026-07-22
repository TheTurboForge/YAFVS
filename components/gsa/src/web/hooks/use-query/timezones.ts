/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useQuery} from '@tanstack/react-query';
import {fetchNativeTimezones} from 'gmp/native-api/timezones';
import useGmp from 'web/hooks/useGmp';
import useSessionToken from 'web/hooks/useSessionToken';

interface UseGetTimezonesParams {
  enabled?: boolean;
}

export const useGetTimezones = ({
  enabled = true,
}: UseGetTimezonesParams = {}) => {
  const gmp = useGmp();
  const token = useSessionToken();

  return useQuery({
    enabled: enabled && Boolean(token),
    queryKey: ['native-timezones', token],
    queryFn: () => fetchNativeTimezones(gmp),
  });
};

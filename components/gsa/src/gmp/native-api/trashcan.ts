/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type {UrlParams} from 'gmp/http/utils';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

export interface NativeTrashcanApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

export interface NativeTrashcanSummaryItem {
  resource_type: string;
  title: string;
  count: number;
}

export interface NativeTrashcanSummary {
  items: NativeTrashcanSummaryItem[];
  total: number;
}

const fetchNativeJson = async <T>(
  gmp: NativeTrashcanApiGmp,
  path: string,
  params: UrlParams = {},
): Promise<T> => {
  const response = await fetch(gmp.buildUrl(path, params), {
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...(gmp.session.jwt ? {Authorization: `Bearer ${gmp.session.jwt}`} : {}),
    },
  });

  if (!response.ok) {
    throw new Error(`Native API request failed with status ${response.status}`);
  }

  return (await response.json()) as T;
};

export const fetchNativeTrashcanSummary = async (
  gmp: NativeTrashcanApiGmp,
): Promise<NativeTrashcanSummary> =>
  fetchNativeJson<NativeTrashcanSummary>(gmp, 'api/v1/trashcan/summary', {
    token: gmp.session.token,
  });

/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import Response from 'gmp/http/response';
import type {UrlParams} from 'gmp/http/utils';

interface NativeApiSession {
  readonly jwt?: string;
  readonly token?: string;
}

interface NativeApiGmp {
  readonly session: NativeApiSession;
  buildUrl(path: string, params?: UrlParams): string;
}

const fetchNativeJson = async <T>(
  gmp: NativeApiGmp,
  path: string,
  params: UrlParams,
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

export const exportNativeResultMetadata = async (
  gmp: NativeApiGmp,
  id: string,
): Promise<Response<string>> => {
  const payload = await fetchNativeJson<unknown>(
    gmp,
    `api/v1/results/${encodeURIComponent(id)}/export`,
    {token: gmp.session.token},
  );
  return new Response(`${JSON.stringify(payload, null, 2)}\n`);
};

export const exportNativeResultsMetadata = async (
  gmp: NativeApiGmp,
  ids: string[],
): Promise<Response<string>> => {
  const results = await Promise.all(
    ids.map(async id => {
      const payload = await fetchNativeJson<unknown>(
        gmp,
        `api/v1/results/${encodeURIComponent(id)}/export`,
        {token: gmp.session.token},
      );
      return payload;
    }),
  );
  return new Response(`${JSON.stringify({results}, null, 2)}\n`);
};

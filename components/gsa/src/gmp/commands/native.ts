/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import type {HttpCommandInputParams} from 'gmp/commands/http';
import Filter from 'gmp/models/filter';
import {isString} from 'gmp/utils/identity';

export const NATIVE_COMMAND_PAGE_SIZE = 500;

export const canUseNativeApi = (http: {buildUrl?: unknown}) =>
  typeof http?.buildUrl === 'function';

export const filterFromCommandParams = (
  params: HttpCommandInputParams = {},
) => {
  const {filter} = params;
  if (filter instanceof Filter) {
    return filter;
  }
  if (isString(filter)) {
    return Filter.fromString(filter);
  }
  return new Filter();
};

export const nativeCollectionMeta = <T>(
  filter: Filter,
  entities: T[],
  total: number,
) => ({
  filter,
  counts: new CollectionCounts({
    first: total > 0 ? 1 : 0,
    all: total,
    filtered: total,
    length: entities.length,
    rows: entities.length,
  }),
});

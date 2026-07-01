/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import {type CollectionList, parseCollectionList} from 'gmp/collection/parser';
import EntitiesCommand from 'gmp/commands/entities';
import type {
  HttpCommandInputParams,
  HttpCommandOptions,
} from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {type XmlResponseData} from 'gmp/http/transform/fast-xml';
import Filter, {type FilterModelElement} from 'gmp/models/filter';
import type {Element} from 'gmp/models/model';
import {isArray, isDefined} from 'gmp/utils/identity';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import {
  fetchNativeFilters,
  nativeFiltersQueryFromFilter,
} from 'gmp/native-api/filters';

interface FilterCountElement {
  page?: number;
  __text?: number;
  filtered?: number;
}

interface FilterPaginationElement {
  _start?: number;
  _max?: number;
}

interface FiltersResponseElement extends Element {
  filters?: Array<FilterModelElement | FilterPaginationElement>;
  filter_count?: FilterCountElement;
}

interface GetFiltersResponseData extends XmlResponseData {
  get_filters?: {
    get_filters_response?: FiltersResponseElement;
  };
}

const isPaginationElement = (
  value: unknown,
): value is FilterPaginationElement => {
  return (
    isDefined(value) &&
    typeof value === 'object' &&
    value !== null &&
    ('_start' in value || '_max' in value)
  );
};

const parseFilterFromResponse = (element: FiltersResponseElement): Filter => {
  const firstFilter =
    isDefined(element.filters) && isArray(element.filters)
      ? element.filters[0]
      : undefined;

  return isDefined(firstFilter) && !isPaginationElement(firstFilter)
    ? Filter.fromElement(firstFilter)
    : Filter.fromElement();
};

const parseCollectionCountsFromResponse = (
  element: FiltersResponseElement,
): CollectionCounts => {
  if (!isArray(element.filters) || !isDefined(element.filter_count)) {
    return new CollectionCounts();
  }

  const pagination = element.filters[1];
  const counts = element.filter_count;
  const first = isPaginationElement(pagination) ? pagination._start : undefined;
  const rows = isPaginationElement(pagination) ? pagination._max : undefined;

  return new CollectionCounts({
    first,
    rows,
    length: counts.page,
    all: counts.__text,
    filtered: counts.filtered,
  });
};

export class FiltersCommand extends EntitiesCommand<Filter> {
  constructor(http: Http) {
    super(http, 'filter', Filter);
  }

  async get(
    params: HttpCommandInputParams = {},
    options?: HttpCommandOptions,
  ) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeFilters(
      this.http,
      nativeFiltersQueryFromFilter(filter),
    );
    return new Response(nativeResponse.filters, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(
    params: HttpCommandInputParams = {},
    options?: HttpCommandOptions,
  ) {
    if (!canUseNativeApi(this.http)) {
      return super.getAll(params, options);
    }

    const filter = filterFromCommandParams(params).all();
    const filters: Filter[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; filters.length < total; page += 1) {
      const nativeResponse = await fetchNativeFilters(this.http, {
        ...nativeFiltersQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      filters.push(...nativeResponse.filters);
      total = nativeResponse.page.total;
      if (nativeResponse.filters.length === 0) {
        break;
      }
    }

    return new Response(
      filters,
      nativeCollectionMeta(
        filter,
        filters,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  getEntitiesResponse(root: XmlResponseData): FiltersResponseElement {
    return (
      (root as GetFiltersResponseData).get_filters?.get_filters_response ?? {}
    );
  }

  getCollectionListFromRoot(root: XmlResponseData): CollectionList<Filter> {
    const response = this.getEntitiesResponse(root);
    const {entities} = parseCollectionList(response, this.name, this.clazz);
    return {
      entities,
      filter: parseFilterFromResponse(response),
      counts: parseCollectionCountsFromResponse(response),
    };
  }
}

export default FiltersCommand;

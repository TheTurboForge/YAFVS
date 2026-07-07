/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntitiesCommand from 'gmp/commands/entities';
import type {HttpCommandInputParams} from 'gmp/commands/http';
import {
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import type Filter from 'gmp/models/filter';
import Tag from 'gmp/models/tag';
import {
  exportNativeTagsMetadata,
  fetchNativeTags,
  nativeTagsQueryFromFilter,
} from 'gmp/native-api/tags';

const shouldExportAllByFilter = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class TagsCommand extends EntitiesCommand<Tag> {
  constructor(http: Http) {
    super(http, 'tag', Tag);
  }

  getEntitiesResponse(root) {
    return root.get_tags.get_tags_response;
  }

  exportByIds(ids: string[]) {
    return exportNativeTagsMetadata(this.http, ids);
  }

  async exportByFilter(filter: Filter) {
    const tags: Tag[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; tags.length < total; page += 1) {
        const nativeResponse = await fetchNativeTags(this.http, {
          ...nativeTagsQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        tags.push(...nativeResponse.tags);
        total = nativeResponse.page.total;
        if (nativeResponse.tags.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeTags(
        this.http,
        nativeTagsQueryFromFilter(filter),
      );
      tags.push(...nativeResponse.tags);
    }

    return exportNativeTagsMetadata(
      this.http,
      tags.map(tag => tag.id as string),
    );
  }

  async get(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeTags(
      this.http,
      nativeTagsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.tags, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params: HttpCommandInputParams = {}) {
    const filter = filterFromCommandParams(params).all();
    const tags: Tag[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; tags.length < total; page += 1) {
      const nativeResponse = await fetchNativeTags(this.http, {
        ...nativeTagsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      tags.push(...nativeResponse.tags);
      total = nativeResponse.page.total;
      if (nativeResponse.tags.length === 0) {
        break;
      }
    }

    return new Response(
      tags,
      nativeCollectionMeta(filter, tags, Number.isFinite(total) ? total : 0),
    );
  }
}

export default TagsCommand;

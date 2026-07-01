/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntitiesCommand from 'gmp/commands/entities';
import type {
  HttpCommandInputParams,
  HttpCommandOptions,
} from 'gmp/commands/http';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Tag from 'gmp/models/tag';
import {fetchNativeTags, nativeTagsQueryFromFilter} from 'gmp/native-api/tags';

class TagsCommand extends EntitiesCommand<Tag> {
  constructor(http: Http) {
    super(http, 'tag', Tag);
  }

  getEntitiesResponse(root) {
    return root.get_tags.get_tags_response;
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

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

  async getAll(
    params: HttpCommandInputParams = {},
    options?: HttpCommandOptions,
  ) {
    if (!canUseNativeApi(this.http)) {
      return super.getAll(params, options);
    }

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

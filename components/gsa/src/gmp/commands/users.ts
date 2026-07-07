/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntitiesCommand from 'gmp/commands/entities';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {type Element} from 'gmp/models/model';
import User from 'gmp/models/user';
import type Filter from 'gmp/models/filter';
import {
  exportNativeUsersMetadata,
  fetchNativeUsers,
  nativeUsersQueryFromFilter,
} from 'gmp/native-api/users';

const shouldExportAllByFilter = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class UsersCommand extends EntitiesCommand<User> {
  constructor(http: Http) {
    super(http, 'user', User);
  }

  getEntitiesResponse(root: Element) {
    // @ts-expect-error
    return root.get_users.get_users_response;
  }

  async get(params = {}, options?) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeUsers(
      this.http,
      nativeUsersQueryFromFilter(filter),
    );
    return new Response(nativeResponse.users, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params = {}, options?) {
    if (!canUseNativeApi(this.http)) {
      return super.getAll(params, options);
    }

    const filter = filterFromCommandParams(params).all();
    const users: User[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; users.length < total; page += 1) {
      const nativeResponse = await fetchNativeUsers(this.http, {
        ...nativeUsersQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      users.push(...nativeResponse.users);
      total = nativeResponse.page.total;
      if (nativeResponse.users.length === 0) {
        break;
      }
    }

    return new Response(
      users,
      nativeCollectionMeta(filter, users, Number.isFinite(total) ? total : 0),
    );
  }

  exportByIds(ids: string[]) {
    if (!canUseNativeApi(this.http)) {
      return super.exportByIds(ids);
    }
    return exportNativeUsersMetadata(this.http, ids);
  }

  export(entities: User[]) {
    if (!canUseNativeApi(this.http)) {
      return super.export(entities);
    }
    return this.exportByIds(
      entities.flatMap(entity =>
        entity.id === undefined ? [] : [entity.id],
      ),
    );
  }

  async exportByFilter(filter: Filter) {
    if (!canUseNativeApi(this.http)) {
      return super.exportByFilter(filter);
    }

    const users: User[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; users.length < total; page += 1) {
        const nativeResponse = await fetchNativeUsers(this.http, {
          ...nativeUsersQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        users.push(...nativeResponse.users);
        total = nativeResponse.page.total;
        if (nativeResponse.users.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeUsers(
        this.http,
        nativeUsersQueryFromFilter(filter),
      );
      users.push(...nativeResponse.users);
    }

    return exportNativeUsersMetadata(
      this.http,
      users.flatMap(user => (user.id === undefined ? [] : [user.id])),
    );
  }
}

export default UsersCommand;

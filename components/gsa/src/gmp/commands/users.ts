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
import {
  fetchNativeUsers,
  nativeUsersQueryFromFilter,
} from 'gmp/native-api/users';

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
}

export default UsersCommand;

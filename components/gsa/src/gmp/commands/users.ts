/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import User from 'gmp/models/user';
import {
  deleteNativeUser,
  exportNativeUsersMetadata,
  fetchUserManagementUsers,
  nativeUserManagementQueryFromFilter,
} from 'gmp/native-api/users';

class UsersCommand {
  private readonly http: Http;

  constructor(http: Http) {
    this.http = http;
  }

  async get(params = {}, _options?) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchUserManagementUsers(
      this.http,
      nativeUserManagementQueryFromFilter(filter),
    );
    return new Response(nativeResponse.users, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params = {}, _options?) {
    const filter = filterFromCommandParams(params).all();
    const users: User[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; users.length < total; page += 1) {
      const nativeResponse = await fetchUserManagementUsers(this.http, {
        ...nativeUserManagementQueryFromFilter(filter),
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
    return exportNativeUsersMetadata(this.http, ids);
  }

  export(entities: User[]) {
    return this.exportByIds(
      entities.flatMap(entity => (entity.id === undefined ? [] : [entity.id])),
    );
  }

  async exportByFilter(filter) {
    const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
    const users =
      Number.isFinite(rows) && rows < 0
        ? (await this.getAll({filter})).data
        : (await this.get({filter})).data;

    return exportNativeUsersMetadata(
      this.http,
      users.flatMap(user => (user.id === undefined ? [] : [user.id])),
    );
  }

  async delete(entities: User[], extraParams: {inheritor_id?: string} = {}) {
    await Promise.all(
      entities.flatMap(entity =>
        entity.id === undefined
          ? []
          : [deleteNativeUser(this.http, entity.id, extraParams.inheritor_id)],
      ),
    );
    return new Response(entities);
  }
}

export default UsersCommand;

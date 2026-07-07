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
import {type XmlResponseData} from 'gmp/http/transform/fast-xml';
import Credential from 'gmp/models/credential';
import type Filter from 'gmp/models/filter';
import {
  exportNativeCredentialsMetadata,
  fetchNativeCredentials,
  nativeCredentialsQueryFromFilter,
} from 'gmp/native-api/credentials';

const shouldExportAllByFilter = (filter: Filter): boolean => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class CredentialsCommand extends EntitiesCommand<Credential> {
  constructor(http: Http) {
    super(http, 'credential', Credential);
  }

  getEntitiesResponse(root: XmlResponseData): XmlResponseData {
    // @ts-expect-error
    return root.get_credentials.get_credentials_response;
  }

  async get(params: HttpCommandInputParams = {}, options?: HttpCommandOptions) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeCredentials(
      this.http,
      nativeCredentialsQueryFromFilter(filter),
    );
    return new Response(nativeResponse.credentials, {
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
    const credentials: Credential[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; credentials.length < total; page += 1) {
      const nativeResponse = await fetchNativeCredentials(this.http, {
        ...nativeCredentialsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      credentials.push(...nativeResponse.credentials);
      total = nativeResponse.page.total;
      if (nativeResponse.credentials.length === 0) {
        break;
      }
    }

    return new Response(
      credentials,
      nativeCollectionMeta(
        filter,
        credentials,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  exportByIds(ids: string[]) {
    if (!canUseNativeApi(this.http)) {
      return super.exportByIds(ids);
    }
    return exportNativeCredentialsMetadata(this.http, ids);
  }

  export(entities: Credential[]) {
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

    const credentials: Credential[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; credentials.length < total; page += 1) {
        const nativeResponse = await fetchNativeCredentials(this.http, {
          ...nativeCredentialsQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        credentials.push(...nativeResponse.credentials);
        total = nativeResponse.page.total;
        if (nativeResponse.credentials.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeCredentials(
        this.http,
        nativeCredentialsQueryFromFilter(filter),
      );
      credentials.push(...nativeResponse.credentials);
    }

    return exportNativeCredentialsMetadata(
      this.http,
      credentials.flatMap(credential =>
        credential.id === undefined ? [] : [credential.id],
      ),
    );
  }
}

export default CredentialsCommand;

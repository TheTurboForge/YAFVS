/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import registerCommand from 'gmp/command';
import EntitiesCommand from 'gmp/commands/entities';
import EntityCommand from 'gmp/commands/entity';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import Response from 'gmp/http/response';
import TlsCertificate from 'gmp/models/tls-certificate';
import {
  deleteNativeTlsCertificate,
  exportNativeTlsCertificateMetadata,
  exportNativeTlsCertificatesMetadata,
  fetchNativeTlsCertificatePem,
  fetchNativeTlsCertificates,
  nativeTlsCertificatesQueryFromFilter,
} from 'gmp/native-api/tls-certificates';

const shouldExportAllByFilter = filter => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

export class TlsCertificateCommand extends EntityCommand {
  constructor(http) {
    super(http, 'tls_certificate', TlsCertificate);
  }

  getElementFromRoot(root) {
    return root.get_tls_certificate.get_tls_certificates_response
      .tls_certificate;
  }

  async export({id}) {
    return await exportNativeTlsCertificateMetadata(this.http, id);
  }

  async delete({id}) {
    if (canUseNativeApi(this.http)) {
      await deleteNativeTlsCertificate(this.http, id);
      return new Response();
    }
    return super.delete({id});
  }

  async get({id}, options = {}) {
    if (
      Object.keys(options).length === 0 &&
      typeof this.http?.buildUrl === 'function'
    ) {
      return await fetchNativeTlsCertificatePem(this.http, id);
    }
    return super.get({id}, options);
  }
}

export class TlsCertificatesCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'tls_certificate', TlsCertificate);
  }

  export(entities) {
    return this.exportByIds(entities.map(entity => entity.id));
  }

  exportByIds(ids) {
    return exportNativeTlsCertificatesMetadata(this.http, ids);
  }

  async exportByFilter(filter) {
    const tlsCertificates = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; tlsCertificates.length < total; page += 1) {
        const nativeResponse = await fetchNativeTlsCertificates(this.http, {
          ...nativeTlsCertificatesQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        tlsCertificates.push(...nativeResponse.tlsCertificates);
        total = nativeResponse.page.total;
        if (nativeResponse.tlsCertificates.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeTlsCertificates(
        this.http,
        nativeTlsCertificatesQueryFromFilter(filter),
      );
      tlsCertificates.push(...nativeResponse.tlsCertificates);
    }

    return exportNativeTlsCertificatesMetadata(
      this.http,
      tlsCertificates.map(cert => cert.id),
    );
  }

  async get(params = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeTlsCertificates(
      this.http,
      nativeTlsCertificatesQueryFromFilter(filter),
    );
    return new Response(nativeResponse.tlsCertificates, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params = {}) {
    const filter = filterFromCommandParams(params).all();
    const tlsCertificates = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; tlsCertificates.length < total; page += 1) {
      const nativeResponse = await fetchNativeTlsCertificates(this.http, {
        ...nativeTlsCertificatesQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      tlsCertificates.push(...nativeResponse.tlsCertificates);
      total = nativeResponse.page.total;
      if (nativeResponse.tlsCertificates.length === 0) {
        break;
      }
    }

    return new Response(
      tlsCertificates,
      nativeCollectionMeta(
        filter,
        tlsCertificates,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  getTimeStatusAggregates({filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'tls_certificate',
      group_column: 'time_status',
      filter,
    });
  }

  getModifiedAggregates({filter} = {}) {
    return this.getAggregates({
      aggregate_type: 'tls_certificate',
      group_column: 'modified',
      filter,
    });
  }
  getEntitiesResponse(root) {
    return root.get_tls_certificates.get_tls_certificates_response;
  }
}

registerCommand('tlscertificate', TlsCertificateCommand);
registerCommand('tlscertificates', TlsCertificatesCommand);

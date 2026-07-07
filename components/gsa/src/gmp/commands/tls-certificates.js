/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import registerCommand from 'gmp/command';
import EntitiesCommand from 'gmp/commands/entities';
import EntityCommand from 'gmp/commands/entity';
import TlsCertificate from 'gmp/models/tls-certificate';
import {
  exportNativeTlsCertificateMetadata,
} from 'gmp/native-api/tls-certificates';

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
}

export class TlsCertificatesCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'tls_certificate', TlsCertificate);
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

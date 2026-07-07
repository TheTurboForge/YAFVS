/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import InfoEntityCommand from 'gmp/commands/info-entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import CertBundAdv from 'gmp/models/cert-bund';
import {exportNativeCertBundAdvisoryMetadata} from 'gmp/native-api/cert-bund-advisories';

class CertBundAdvisoryCommand extends InfoEntityCommand<CertBundAdv> {
  constructor(http: Http) {
    super(http, 'cert_bund_adv', CertBundAdv);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeCertBundAdvisoryMetadata(this.http, id);
  }
}

export default CertBundAdvisoryCommand;

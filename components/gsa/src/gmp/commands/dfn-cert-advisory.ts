/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import InfoEntityCommand from 'gmp/commands/info-entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import DfnCertAdv from 'gmp/models/dfn-cert';
import {exportNativeDfnCertAdvisoryMetadata} from 'gmp/native-api/dfn-cert-advisories';

class DfnCertAdvisoryCommand extends InfoEntityCommand<DfnCertAdv> {
  constructor(http: Http) {
    super(http, 'dfn_cert_adv', DfnCertAdv);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeDfnCertAdvisoryMetadata(this.http, id);
  }
}

export default DfnCertAdvisoryCommand;

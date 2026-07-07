/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import InfoEntityCommand from 'gmp/commands/info-entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import CVE from 'gmp/models/cve';
import {exportNativeCveMetadata} from 'gmp/native-api/cves';

class CveCommand extends InfoEntityCommand<CVE> {
  constructor(http: Http) {
    super(http, 'cve', CVE);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeCveMetadata(this.http, id);
  }
}

export default CveCommand;

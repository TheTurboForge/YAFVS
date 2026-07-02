/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import InfoEntityCommand from 'gmp/commands/info-entity';
import {canUseNativeApi} from 'gmp/commands/native';
import type {EntityCommandParams} from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import CVE from 'gmp/models/cve';
import {exportNativeCveMetadata} from 'gmp/native-api/cves';

class CveCommand extends InfoEntityCommand<CVE> {
  constructor(http: Http) {
    super(http, 'cve', CVE);
  }

  async export({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      try {
        return await exportNativeCveMetadata(this.http, id);
      } catch {
        // Keep inherited info bulk export responsible for legacy CVE export behavior.
      }
    }
    return super.export({id});
  }
}

export default CveCommand;

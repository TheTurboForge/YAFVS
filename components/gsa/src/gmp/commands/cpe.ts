/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import InfoEntityCommand from 'gmp/commands/info-entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Cpe from 'gmp/models/cpe';
import {exportNativeCpeMetadata, fetchNativeCpe} from 'gmp/native-api/cpes';

class CpeCommand extends InfoEntityCommand<Cpe> {
  constructor(http: Http) {
    super(http, 'cpe', Cpe);
  }

  async get({id}: EntityCommandParams) {
    const cpe = await fetchNativeCpe(this.http, id);
    return new Response(cpe);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeCpeMetadata(this.http, id);
  }
}

export default CpeCommand;

/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import InfoEntityCommand from 'gmp/commands/info-entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import Nvt from 'gmp/models/nvt';
import {exportNativeNvtMetadata} from 'gmp/native-api/nvts';

class NvtCommand extends InfoEntityCommand<Nvt> {
  constructor(http: Http) {
    super(http, 'nvt', Nvt);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeNvtMetadata(this.http, id);
  }

  async getConfigNvt({oid, configId}: {oid: string; configId: string}) {
    const response = await this.httpGetWithTransform(
      {
        cmd: 'get_config_nvt',
        config_id: configId,
        oid,
      },
      {includeDefaultParams: false},
    );
    const {data} = response;
    const configResponse = data.get_config_nvt_response;
    // @ts-expect-error
    const nvt = Nvt.fromElement(configResponse.get_nvts_response);
    return response.setData(nvt);
  }
}

export default NvtCommand;

/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand from 'gmp/commands/entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import logger from 'gmp/log';
import {type Element} from 'gmp/models/model';
import Result from 'gmp/models/result';
import {exportNativeResultMetadata} from 'gmp/native-api/results';

const log = logger.getLogger('gmp.commands.result');

export class ResultCommand extends EntityCommand<Result> {
  constructor(http: Http) {
    super(http, 'result', Result);
  }

  async export({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      try {
        return await exportNativeResultMetadata(this.http, id);
      } catch (error) {
        log.debug(
          'Native result metadata export failed, falling back to GMP',
          error,
        );
      }
    }
    return super.export({id});
  }

  getElementFromRoot(root: Element): Element {
    // @ts-expect-error
    return root.get_result.get_results_response.result;
  }
}

/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand from 'gmp/commands/entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import {canUseNativeApi} from 'gmp/commands/native';
import Response from 'gmp/http/response';
import type Http from 'gmp/http/http';
import {type Element} from 'gmp/models/model';
import Result from 'gmp/models/result';
import {exportNativeResultMetadata} from 'gmp/native-api/results';
import {fetchNativeResult} from 'gmp/native-api/reports';

export class ResultCommand extends EntityCommand<Result> {
  constructor(http: Http) {
    super(http, 'result', Result);
  }

  async get({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      const nativeResponse = await fetchNativeResult(this.http, id);
      return new Response(nativeResponse.result);
    }
    return super.get({id});
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeResultMetadata(this.http, id);
  }

  getElementFromRoot(root: Element): Element {
    // @ts-expect-error
    return root.get_result.get_results_response.result;
  }
}

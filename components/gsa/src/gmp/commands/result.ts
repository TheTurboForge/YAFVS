/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand from 'gmp/commands/entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import {type Element} from 'gmp/models/model';
import Result from 'gmp/models/result';
import {exportNativeResultMetadata} from 'gmp/native-api/results';

export class ResultCommand extends EntityCommand<Result> {
  constructor(http: Http) {
    super(http, 'result', Result);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeResultMetadata(this.http, id);
  }

  getElementFromRoot(root: Element): Element {
    // @ts-expect-error
    return root.get_result.get_results_response.result;
  }
}

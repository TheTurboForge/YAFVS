/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {fetchNativeResult} from 'gmp/native-api/reports';
import {exportNativeResultMetadata} from 'gmp/native-api/results';

interface ResultCommandParams {
  id: string;
}

export class ResultCommand extends HttpCommand {
  constructor(http: Http) {
    super(http);
  }

  async get({id}: ResultCommandParams) {
    const nativeResponse = await fetchNativeResult(this.http, id);
    return new Response(nativeResponse.result);
  }

  async export({id}: ResultCommandParams) {
    return await exportNativeResultMetadata(this.http, id);
  }
}

/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {fetchNativeTimezones} from 'gmp/native-api/timezones';

class TimezonesCommand extends HttpCommand {
  constructor(http: Http) {
    super(http);
  }

  async get() {
    return new Response(await fetchNativeTimezones(this.http));
  }
}

export default TimezonesCommand;

/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {map} from 'gmp/utils/array';
import {fetchNativeTimezones} from 'gmp/native-api/timezones';

class TimezonesCommand extends HttpCommand {
  constructor(http: Http) {
    super(http, {cmd: 'get_timezones'});
  }

  async get() {
    if (canUseNativeApi(this.http)) {
      return new Response(await fetchNativeTimezones(this.http));
    }

    const response = await this.httpGetWithTransform();
    const {data} = response;
    const {timezone: timezones} =
      // @ts-expect-error
      data.get_timezones.get_timezones_response;
    return response.set(map(timezones, tz => tz.name));
  }
}

export default TimezonesCommand;

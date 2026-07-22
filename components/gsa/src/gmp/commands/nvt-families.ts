/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {fetchNativeNvtFamilies} from 'gmp/native-api/nvt-families';

class NvtFamiliesCommand extends HttpCommand {
  constructor(http: Http) {
    super(http);
  }

  async get() {
    return new Response(await fetchNativeNvtFamilies(this.http));
  }
}

export default NvtFamiliesCommand;

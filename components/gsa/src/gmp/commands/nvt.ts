/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type {EntityCommandParams} from 'gmp/commands/entity';
import InfoEntityCommand from 'gmp/commands/info-entity';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Nvt from 'gmp/models/nvt';
import type ScanConfig from 'gmp/models/scan-config';
import {exportNativeNvtMetadata, fetchNativeNvt} from 'gmp/native-api/nvts';
import {fetchNativeScanConfig} from 'gmp/native-api/scan-configs';

const isTimeoutPreference = (preference: {
  id?: string | number;
  name?: string;
  type?: string;
}) =>
  String(preference.id) === '0' &&
  preference.name === 'timeout' &&
  preference.type === 'entry';

const configuredTimeout = (value: string | number | undefined) => {
  const timeout = Number.parseFloat(String(value ?? ''));
  return Number.isFinite(timeout) ? timeout : undefined;
};

export const composeNativeConfigNvt = (
  nvt: Nvt,
  scanConfig: ScanConfig,
  oid: string,
): Nvt => {
  const configuredPreferences = scanConfig.preferences.nvt.filter(
    preference => preference.nvt?.oid === oid,
  );
  const timeout = configuredPreferences.find(isTimeoutPreference);
  const preferences = configuredPreferences
    .filter(preference => !isTimeoutPreference(preference))
    .map(({nvt: _nvt, ...preference}) => preference) as Nvt['preferences'];

  return Object.assign(Object.create(Object.getPrototypeOf(nvt)), nvt, {
    preferences,
    timeout: configuredTimeout(timeout?.value),
  });
};

class NvtCommand extends InfoEntityCommand<Nvt> {
  constructor(http: Http) {
    super(http, 'nvt', Nvt);
  }

  async get({id}: EntityCommandParams) {
    const {nvt} = await fetchNativeNvt(this.http, id);
    return new Response(nvt);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeNvtMetadata(this.http, id);
  }

  async getConfigNvt({oid, configId}: {oid: string; configId: string}) {
    const [nativeNvt, scanConfig] = await Promise.all([
      fetchNativeNvt(this.http, oid),
      fetchNativeScanConfig(this.http, configId),
    ]);
    return new Response(
      composeNativeConfigNvt(nativeNvt.nvt, scanConfig.scanConfig, oid),
    );
  }
}

export default NvtCommand;

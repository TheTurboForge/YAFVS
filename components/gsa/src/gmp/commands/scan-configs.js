/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import registerCommand from 'gmp/command';
import EntitiesCommand from 'gmp/commands/entities';
import EntityCommand from 'gmp/commands/entity';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import Response from 'gmp/http/response';
import logger from 'gmp/log';
import Nvt from 'gmp/models/nvt';
import ScanConfig from 'gmp/models/scan-config';
import {
  cloneNativeScanConfig,
  deleteNativeScanConfig,
  fetchNativeScanConfigs,
  nativeScanConfigsQueryFromFilter,
  patchNativeScanConfig,
} from 'gmp/native-api/scan-configs';
import {YES_VALUE, NO_VALUE} from 'gmp/parser';
import {forEach, map} from 'gmp/utils/array';
import {isDefined} from 'gmp/utils/identity';

const log = logger.getLogger('gmp.commands.scanconfigs');

const isEmptyOptionalObject = value =>
  !isDefined(value) || Object.keys(value).length === 0;

const canPatchMetadataNatively = ({
  familyTrend,
  scannerPreferenceValues,
  select,
  trend,
}) =>
  !isDefined(familyTrend) &&
  isEmptyOptionalObject(scannerPreferenceValues) &&
  isEmptyOptionalObject(select) &&
  isEmptyOptionalObject(trend);

export const convert = (values, prefix) => {
  const ret = {};
  for (const [key, value] of Object.entries(values)) {
    ret[prefix + key] = value;
  }
  return ret;
};

export const convertSelect = (values, prefix) => {
  const ret = {};
  for (const [key, value] of Object.entries(values)) {
    if (value === YES_VALUE) {
      ret[prefix + key] = value;
    }
  }
  return ret;
};

export const convertPreferences = (values = {}, nvtOid) => {
  const ret = {};
  for (const [prop, data] of Object.entries(values)) {
    const {id, type, value} = data;
    if (isDefined(value)) {
      const typestring = nvtOid + ':' + id + ':' + type + ':' + prop;
      if (type === 'password') {
        ret['password:' + typestring] = 'yes';
      } else if (type === 'file') {
        ret['file:' + typestring] = 'yes';
      }
      ret['preference:' + typestring] = value;
    }
  }
  return ret;
};

export class ScanConfigCommand extends EntityCommand {
  constructor(http) {
    super(http, 'config', ScanConfig);
  }

  import({xml_file}) {
    const data = {
      cmd: 'import_config',
      xml_file,
    };
    log.debug('Importing scan config', data);
    return this.httpPostWithTransform(data);
  }

  create({baseScanConfig, name, comment}) {
    const data = {
      cmd: 'create_config',
      base: baseScanConfig,
      comment,
      name,
      usage_type: 'scan',
    };
    log.debug('Creating scanconfig', data);
    return this.action(data);
  }

  async clone({id}) {
    if (canUseNativeApi(this.http)) {
      try {
        return await cloneNativeScanConfig(this.http, id);
      } catch (error) {
        log.debug(
          'Native scan config clone failed, falling back to GMP',
          error,
        );
      }
    }
    return super.clone({id});
  }

  async delete({id}) {
    if (canUseNativeApi(this.http)) {
      await deleteNativeScanConfig(this.http, id);
      return;
    }
    return super.delete({id});
  }

  save({
    id,
    name,
    comment = '',
    trend,
    familyTrend,
    select,
    scannerPreferenceValues,
  }) {
    if (
      canUseNativeApi(this.http) &&
      canPatchMetadataNatively({
        familyTrend,
        scannerPreferenceValues,
        select,
        trend,
      })
    ) {
      return patchNativeScanConfig(this.http, id, {comment, name});
    }

    const trendData = isDefined(trend) ? convert(trend, 'trend:') : {};
    const scannerPreferenceData = isDefined(scannerPreferenceValues)
      ? convert(scannerPreferenceValues, 'preference:scanner:scanner:scanner:')
      : {};

    const selectData = isDefined(select)
      ? convertSelect(select, 'select:')
      : {};
    const data = {
      ...trendData,
      ...scannerPreferenceData,
      ...selectData,
      cmd: 'save_config',
      id,
      comment,
      name,
      trend: familyTrend,
    };
    log.debug('Saving scanconfig', data);
    return this.action(data);
  }

  saveScanConfigFamily({id, familyName, selected}) {
    const data = {
      ...convertSelect(selected, 'nvt:'),
      cmd: 'save_config_family',
      id,
      family: familyName,
    };
    log.debug('Saving scanconfigfamily', data);
    return this.httpPostWithTransform(data);
  }

  editScanConfigFamilySettings({id, familyName}) {
    const get = this.httpGetWithTransform({
      cmd: 'edit_config_family',
      id,
      family: familyName,
    });
    const all = this.httpGetWithTransform({
      cmd: 'edit_config_family_all',
      id,
      family: familyName,
    });
    return Promise.all([get, all]).then(([response, response_all]) => {
      const {data} = response;
      const data_all = response_all.data;
      const config_resp = data.get_config_family_response;
      const config_resp_all = data_all.get_config_family_response;
      const settings = {};

      const nvts = {};
      forEach(config_resp.get_nvts_response.nvt, nvt => {
        const oid = nvt._oid;
        nvts[oid] = true;
      });

      settings.nvts = map(config_resp_all.get_nvts_response.nvt, nvt => {
        nvt.oid = nvt._oid;
        delete nvt._oid;

        nvt.severity = nvt.cvss_base;
        delete nvt.cvss_base;

        nvt.selected = nvt.oid in nvts ? YES_VALUE : NO_VALUE;
        return nvt;
      });

      return response.setData(settings);
    });
  }

  saveScanConfigNvt({id, timeout, oid, preferenceValues}) {
    const data = {
      ...convertPreferences(preferenceValues, oid),
      cmd: 'save_config_nvt',
      id,
      oid,
      timeout: isDefined(timeout) ? 1 : 0,
    };

    data['preference:' + oid + ':0:entry:timeout'] = isDefined(timeout)
      ? timeout
      : '';

    log.debug('Saving scanconfignvt', data);
    return this.httpPostWithTransform(data);
  }

  editScanConfigNvtSettings({id, oid}) {
    return this.httpGetWithTransform({
      cmd: 'get_config_nvt',
      id,
      oid,
      name: '', // don't matter
    }).then(response => {
      const {data} = response;
      const config_resp = data.get_config_nvt_response;

      const nvt = Nvt.fromElement(config_resp.get_nvts_response);

      return response.setData(nvt);
    });
  }

  getElementFromRoot(root) {
    return root.get_config.get_configs_response.config;
  }
}

class ScanConfigsCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'config', ScanConfig);
  }

  getEntitiesResponse(root) {
    return root.get_configs.get_configs_response;
  }

  get(params, options) {
    if (canUseNativeApi(this.http)) {
      const filter = filterFromCommandParams(params);
      return fetchNativeScanConfigs(
        this.http,
        nativeScanConfigsQueryFromFilter(filter),
      ).then(
        nativeResponse =>
          new Response(nativeResponse.scanConfigs, {
            filter,
            counts: nativeResponse.counts,
          }),
      );
    }

    params = {...params, usage_type: 'scan'};
    return this.httpGetWithTransform(params, options).then(response => {
      const {entities, filter, counts} = this.getCollectionListFromRoot(
        response.data,
      );
      return response.set(entities, {filter, counts});
    });
  }

  async getAll(params = {}, options) {
    if (!canUseNativeApi(this.http)) {
      return super.getAll(params, options);
    }

    const filter = filterFromCommandParams(params).all();
    const scanConfigs = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; scanConfigs.length < total; page += 1) {
      const nativeResponse = await fetchNativeScanConfigs(this.http, {
        ...nativeScanConfigsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      scanConfigs.push(...nativeResponse.scanConfigs);
      total = nativeResponse.page.total;
      if (nativeResponse.scanConfigs.length === 0) {
        break;
      }
    }

    return new Response(
      scanConfigs,
      nativeCollectionMeta(
        filter,
        scanConfigs,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }
}

registerCommand('scanconfig', ScanConfigCommand);
registerCommand('scanconfigs', ScanConfigsCommand);

export {ScanConfigsCommand};

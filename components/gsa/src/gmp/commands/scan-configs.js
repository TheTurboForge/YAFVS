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
import ScanConfig, {
  SCANCONFIG_TREND_DYNAMIC,
  SCANCONFIG_TREND_STATIC,
} from 'gmp/models/scan-config';
import {
  cloneNativeScanConfig,
  createNativeScanConfig,
  deleteNativeScanConfig,
  exportNativeScanConfigsMetadata,
  exportNativeScanConfigMetadata,
  fetchNativeScanConfigFamilyNvts,
  fetchNativeScanConfigWithFamilies,
  fetchNativeScanConfigs,
  getNativeScanConfigFamilyNvtChanges,
  MAX_SCAN_CONFIG_FAMILY_NVT_SELECTION_CHANGES,
  nativeScanConfigsQueryFromFilter,
  patchNativeScanConfig,
  patchNativeScanConfigFamilyNvts,
} from 'gmp/native-api/scan-configs';
import {YES_VALUE, NO_VALUE} from 'gmp/parser';
import {forEach, map} from 'gmp/utils/array';
import {isDefined} from 'gmp/utils/identity';

const log = logger.getLogger('gmp.commands.scanconfigs');

const shouldExportAllByFilter = filter => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

const isFamilyMap = value =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

const hasOwn = (object, key) =>
  Object.prototype.hasOwnProperty.call(object, key);

const createNativeFamilySelection = ({familyTrend, trend, select}) => {
  if (!isFamilyMap(trend) || !isFamilyMap(select)) {
    throw new Error(
      'Native scan config family selection requires both trend and select maps',
    );
  }
  if (
    familyTrend !== SCANCONFIG_TREND_DYNAMIC &&
    familyTrend !== SCANCONFIG_TREND_STATIC
  ) {
    throw new Error(
      'Native scan config family selection requires an explicit family trend',
    );
  }

  const familyNames = [
    ...new Set([...Object.keys(trend), ...Object.keys(select)]),
  ].sort();

  if (familyNames.length === 0) {
    throw new Error(
      'Native scan config family selection maps must contain at least one family',
    );
  }
  const missingTrend = familyNames.filter(name => !hasOwn(trend, name));
  const missingSelect = familyNames.filter(name => !hasOwn(select, name));
  if (missingTrend.length > 0 || missingSelect.length > 0) {
    const missing = [
      ...(missingTrend.length > 0 ? [`trend: ${missingTrend.join(', ')}`] : []),
      ...(missingSelect.length > 0 ? [`select: ${missingSelect.join(', ')}`] : []),
    ];
    throw new Error(
      `Native scan config family selection maps must contain every family in both maps (missing ${missing.join('; ')})`,
    );
  }
  if (
    familyNames.some(
      name =>
        trend[name] !== SCANCONFIG_TREND_DYNAMIC &&
        trend[name] !== SCANCONFIG_TREND_STATIC,
    )
  ) {
    throw new Error(
      'Native scan config family trends must be explicitly static or dynamic',
    );
  }
  if (
    familyNames.some(
      name => select[name] !== YES_VALUE && select[name] !== NO_VALUE,
    )
  ) {
    throw new Error(
      'Native scan config family selections must be explicitly yes or no',
    );
  }

  return {
    'families_growing': familyTrend === SCANCONFIG_TREND_DYNAMIC,
    families: familyNames.map(name => ({
      growing: trend[name] === SCANCONFIG_TREND_DYNAMIC,
      name,
      selected: select[name] === YES_VALUE,
    })),
  };
};

const canPatchMetadataNatively = ({familyTrend, select, trend}) =>
  !isDefined(familyTrend) && !isDefined(select) &&
  !isDefined(trend);

const createNativeScannerPreferenceMutations = (values = {}) =>
  Object.entries(values).flatMap(([name, value]) =>
    isDefined(value)
      ? [
          {
            scope: 'scanner',
            name,
            action: 'set',
            value: String(value),
          },
        ]
      : [],
  );

const createNativeNvtPreferenceMutations = (values = {}, oid) =>
  Object.entries(values).flatMap(([name, {id, type, value}]) =>
    isDefined(value)
      ? [
          {
            scope: 'nvt',
            name,
            action: 'set',
            value: String(value),
            nvt: {oid, id, type},
          },
        ]
      : [],
  );

const createNativeNvtTimeoutMutation = (timeout, oid) => ({
  scope: 'nvt',
  name: 'timeout',
  action: isDefined(timeout) ? 'set' : 'reset',
  ...(isDefined(timeout) ? {value: String(timeout)} : {}),
  nvt: {oid, id: 0, type: 'entry'},
});

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

  async get({id}, options) {
    if (!canUseNativeApi(this.http)) {
      return await super.get({id}, options);
    }

    const response = await fetchNativeScanConfigWithFamilies(this.http, id);
    return new Response(response.scanConfig);
  }

  async export({id}) {
    return await exportNativeScanConfigMetadata(this.http, id);
  }

  async create({baseScanConfig, name, comment}) {
    if (!canUseNativeApi(this.http)) {
      throw new Error('Native API scan config creation is unavailable');
    }

    return await createNativeScanConfig(this.http, {
      base_scan_config_id: baseScanConfig,
      comment: comment ?? '',
      name,
    });
  }

  async clone({id}) {
    if (canUseNativeApi(this.http)) {
      return await cloneNativeScanConfig(this.http, id);
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
    if (canUseNativeApi(this.http)) {
      const preferences = createNativeScannerPreferenceMutations(
        scannerPreferenceValues,
      );

      if (
        canPatchMetadataNatively({
          familyTrend,
          select,
          trend,
        })
      ) {
        return patchNativeScanConfig(this.http, id, {
          comment,
          name,
          ...(preferences.length > 0 ? {preferences} : {}),
        });
      }

      const familySelection = createNativeFamilySelection({
        familyTrend,
        select,
        trend,
      });
      return patchNativeScanConfig(this.http, id, {
        comment,
        'family_selection': familySelection,
        name,
        ...(preferences.length > 0 ? {preferences} : {}),
      });
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
    log.debug('Saving scanconfig');
    return this.action(data);
  }

  saveScanConfigFamily({id, familyName, selected, nvts}) {
    if (canUseNativeApi(this.http)) {
      const changes = getNativeScanConfigFamilyNvtChanges(nvts ?? [], selected);
      if (changes.length === 0) {
        return Promise.resolve();
      }
      if (changes.length > MAX_SCAN_CONFIG_FAMILY_NVT_SELECTION_CHANGES) {
        return Promise.reject(
          new Error(
            `A single scan config family save may change at most ${MAX_SCAN_CONFIG_FAMILY_NVT_SELECTION_CHANGES} NVTs`,
          ),
        );
      }
      return patchNativeScanConfigFamilyNvts(this.http, id, familyName, {
        changes,
      });
    }

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
    if (canUseNativeApi(this.http)) {
      return fetchNativeScanConfigFamilyNvts(this.http, id, familyName).then(
        data => new Response(data),
      );
    }

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
    if (canUseNativeApi(this.http)) {
      return patchNativeScanConfig(this.http, id, {
        preferences: [
          ...createNativeNvtPreferenceMutations(preferenceValues, oid),
          createNativeNvtTimeoutMutation(timeout, oid),
        ],
      });
    }

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

    log.debug('Saving scanconfignvt');
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

  exportByIds(ids) {
    return exportNativeScanConfigsMetadata(this.http, ids);
  }

  export(entities) {
    return this.exportByIds(entities.map(entity => entity.id));
  }

  async exportByFilter(filter) {
    const scanConfigs = [];
    if (shouldExportAllByFilter(filter)) {
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
    } else {
      const nativeResponse = await fetchNativeScanConfigs(
        this.http,
        nativeScanConfigsQueryFromFilter(filter),
      );
      scanConfigs.push(...nativeResponse.scanConfigs);
    }

    return exportNativeScanConfigsMetadata(
      this.http,
      scanConfigs.map(scanConfig => scanConfig.id),
    );
  }

  get(params, options) {
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

  async getAll(params = {}, options) {
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

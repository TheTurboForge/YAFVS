/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import registerCommand from 'gmp/command';
import EntitiesCommand from 'gmp/commands/entities';
import EntityCommand from 'gmp/commands/entity';
import {
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import Response from 'gmp/http/response';
import ScanConfig, {
  SCANCONFIG_TREND_DYNAMIC,
  SCANCONFIG_TREND_STATIC,
} from 'gmp/models/scan-config';
import {
  cloneNativeScanConfig,
  createNativeScanConfig,
  deleteNativeScanConfig,
  downloadNativeScanConfigBackup,
  exportNativeScanConfigsMetadata,
  fetchNativeScanConfigFamilyNvts,
  fetchNativeScanConfigWithFamilies,
  fetchNativeScanConfigs,
  getNativeScanConfigFamilyNvtChanges,
  MAX_SCAN_CONFIG_FAMILY_NVT_SELECTION_CHANGES,
  nativeScanConfigsQueryFromFilter,
  patchNativeScanConfig,
  patchNativeScanConfigFamilyNvts,
  importNativeScanConfigBackup,
} from 'gmp/native-api/scan-configs';
import {YES_VALUE, NO_VALUE} from 'gmp/parser';
import {isDefined} from 'gmp/utils/identity';

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
      ...(missingSelect.length > 0
        ? [`select: ${missingSelect.join(', ')}`]
        : []),
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
    families_growing: familyTrend === SCANCONFIG_TREND_DYNAMIC,
    families: familyNames.map(name => ({
      growing: trend[name] === SCANCONFIG_TREND_DYNAMIC,
      name,
      selected: select[name] === YES_VALUE,
    })),
  };
};

const canPatchMetadataNatively = ({familyTrend, select, trend}) =>
  !isDefined(familyTrend) && !isDefined(select) && !isDefined(trend);

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

export class ScanConfigCommand extends EntityCommand {
  constructor(http) {
    super(http, 'config', ScanConfig);
  }

  async import({jsonFile}) {
    if (!jsonFile) {
      throw new Error('A scan config backup JSON file is required.');
    }
    const content =
      typeof jsonFile === 'string' ? jsonFile : await jsonFile.text();
    let backup;
    try {
      backup = JSON.parse(content);
    } catch {
      throw new Error('Scan config backup must contain valid JSON.');
    }
    if (
      backup === null ||
      typeof backup !== 'object' ||
      Array.isArray(backup)
    ) {
      throw new Error('Scan config backup must contain a JSON object.');
    }
    return importNativeScanConfigBackup(this.http, backup);
  }

  async get({id}) {
    const response = await fetchNativeScanConfigWithFamilies(this.http, id);
    return new Response(response.scanConfig);
  }

  async export({id}) {
    return await downloadNativeScanConfigBackup(this.http, id);
  }

  async create({baseScanConfig, name, comment}) {
    return await createNativeScanConfig(this.http, {
      base_scan_config_id: baseScanConfig,
      comment: comment ?? '',
      name,
    });
  }

  async clone({id}) {
    return await cloneNativeScanConfig(this.http, id);
  }

  async delete({id}) {
    await deleteNativeScanConfig(this.http, id);
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
      family_selection: familySelection,
      name,
      ...(preferences.length > 0 ? {preferences} : {}),
    });
  }

  saveScanConfigFamily({id, familyName, selected, nvts}) {
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

  editScanConfigFamilySettings({id, familyName}) {
    return fetchNativeScanConfigFamilyNvts(this.http, id, familyName).then(
      data => new Response(data),
    );
  }

  saveScanConfigNvt({id, timeout, oid, preferenceValues}) {
    return patchNativeScanConfig(this.http, id, {
      preferences: [
        ...createNativeNvtPreferenceMutations(preferenceValues, oid),
        createNativeNvtTimeoutMutation(timeout, oid),
      ],
    });
  }
}

class ScanConfigsCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'config', ScanConfig);
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

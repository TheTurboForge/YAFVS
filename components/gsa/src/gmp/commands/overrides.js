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
import Override, {
  ANY,
  MANUAL,
  ACTIVE_YES_ALWAYS_VALUE,
  ACTIVE_YES_FOR_NEXT_VALUE,
  ACTIVE_YES_UNTIL_VALUE,
  DEFAULT_DAYS,
  RESULT_UUID,
  SEVERITY_FALSE_POSITIVE,
  TASK_SELECTED,
} from 'gmp/models/override';
import {
  cloneNativeOverride,
  createNativeOverride,
  deleteNativeOverride,
  exportNativeOverrideMetadata,
  exportNativeOverridesMetadata,
  fetchNativeOverride,
  fetchNativeOverrides,
  nativeOverridesQueryFromFilter,
  patchNativeOverride,
} from 'gmp/native-api/overrides';
import {NO_VALUE, YES_VALUE} from 'gmp/parser';

const canUseNativeApi = http => typeof http?.buildUrl === 'function';

const requireNativeOverrideApi = http => {
  if (!canUseNativeApi(http)) {
    throw new Error('Native override API is required for override command');
  }
};

const nullableValue = value => (value === '' ? null : value);

const nativeHostsOrPort = (selection, manual) =>
  selection === MANUAL ? nullableValue(manual) : null;

const nativeReferenceId = (selection, uuid, selectedValue) =>
  selection === selectedValue ? nullableValue(uuid) : null;

const nativeActivation = (active, days, isCreate = false) => {
  const value =
    active === undefined && isCreate ? ACTIVE_YES_ALWAYS_VALUE : active;

  switch (String(value)) {
    case ACTIVE_YES_ALWAYS_VALUE:
      return {mode: 'always'};
    case ACTIVE_YES_FOR_NEXT_VALUE:
      return {mode: 'for_days', days: Number(days)};
    case ACTIVE_YES_UNTIL_VALUE:
      return undefined;
    default:
      return {mode: 'inactive'};
  }
};

const isCustomSeverity = value =>
  value === YES_VALUE || value === String(YES_VALUE);

const nativeNewSeverity = ({
  custom_severity,
  newSeverity,
  new_severity_from_list,
}) =>
  isCustomSeverity(custom_severity) ? newSeverity : new_severity_from_list;

const nativeOverrideCreateArgs = ({
  oid,
  active = ACTIVE_YES_ALWAYS_VALUE,
  days = DEFAULT_DAYS,
  hosts = ANY,
  hosts_manual = '',
  port = ANY,
  port_manual = '',
  result_id = '',
  result_uuid = '',
  severity = '',
  task_id = '',
  task_uuid = '',
  text,
  custom_severity = NO_VALUE,
  newSeverity = '',
  new_severity_from_list = SEVERITY_FALSE_POSITIVE,
}) => ({
  nvt_id: oid,
  text,
  hosts: nativeHostsOrPort(hosts, hosts_manual),
  port: nativeHostsOrPort(port, port_manual),
  severity: nullableValue(severity),
  new_severity: nativeNewSeverity({
    custom_severity,
    newSeverity,
    new_severity_from_list,
  }),
  task_id: nativeReferenceId(task_id, task_uuid, TASK_SELECTED),
  result_id: nativeReferenceId(result_id, result_uuid, RESULT_UUID),
  activation: nativeActivation(active, days, true),
});

const nativeOverridePatchArgs = ({
  id,
  oid,
  active,
  days,
  hosts,
  hosts_manual,
  port,
  port_manual,
  result_id,
  result_uuid,
  severity,
  task_id,
  task_uuid,
  text,
  custom_severity,
  newSeverity,
  new_severity_from_list,
}) => {
  const args = {id};

  if (oid !== undefined) args.nvt_id = oid;
  if (text !== undefined) args.text = text;
  if (hosts !== undefined) args.hosts = nativeHostsOrPort(hosts, hosts_manual);
  if (port !== undefined) args.port = nativeHostsOrPort(port, port_manual);
  if (severity !== undefined) args.severity = nullableValue(severity);
  if (task_id !== undefined) {
    args.task_id = nativeReferenceId(task_id, task_uuid, TASK_SELECTED);
  }
  if (result_id !== undefined) {
    args.result_id = nativeReferenceId(result_id, result_uuid, RESULT_UUID);
  }
  if (
    custom_severity !== undefined ||
    newSeverity !== undefined ||
    new_severity_from_list !== undefined
  ) {
    const value = nativeNewSeverity({
      custom_severity,
      newSeverity,
      new_severity_from_list,
    });
    if (value !== undefined && value !== '') args.new_severity = value;
  }
  if (active !== undefined) {
    const activation = nativeActivation(active, days);
    if (activation !== undefined) args.activation = activation;
  }

  return args;
};

const shouldExportAllByFilter = filter => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class OverrideCommand extends EntityCommand {
  constructor(http) {
    super(http, 'override', Override);
  }

  async get({id}) {
    requireNativeOverrideApi(this.http);
    return new Response(await fetchNativeOverride(this.http, id));
  }

  create(args) {
    requireNativeOverrideApi(this.http);
    return createNativeOverride(this.http, nativeOverrideCreateArgs(args));
  }

  save(args) {
    requireNativeOverrideApi(this.http);
    return patchNativeOverride(this.http, nativeOverridePatchArgs(args));
  }

  async clone({id}) {
    requireNativeOverrideApi(this.http);
    return await cloneNativeOverride(this.http, id);
  }

  async export({id}) {
    return await exportNativeOverrideMetadata(this.http, id);
  }

  async delete({id}) {
    await deleteNativeOverride(this.http, id);
  }
}

class OverridesCommand extends EntitiesCommand {
  constructor(http) {
    super(http, 'override', Override);
    this.setDefaultParam('details', 1);
  }

  exportByIds(ids) {
    return exportNativeOverridesMetadata(this.http, ids);
  }

  export(entities) {
    return this.exportByIds(entities.map(entity => entity.id));
  }

  async exportByFilter(filter) {
    const overrides = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; overrides.length < total; page += 1) {
        const nativeResponse = await fetchNativeOverrides(this.http, {
          ...nativeOverridesQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        overrides.push(...nativeResponse.overrides);
        total = nativeResponse.page.total;
        if (nativeResponse.overrides.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeOverrides(
        this.http,
        nativeOverridesQueryFromFilter(filter),
      );
      overrides.push(...nativeResponse.overrides);
    }

    return exportNativeOverridesMetadata(
      this.http,
      overrides.map(override => override.id),
    );
  }

  async delete(entities) {
    await this.deleteByIds(entities.map(entity => entity.id));
    return new Response(entities);
  }

  async deleteByIds(ids) {
    for (const id of ids) {
      await deleteNativeOverride(this.http, id);
    }
    return new Response(ids);
  }

  async deleteByFilter(filter) {
    const response = await this.get({filter});
    const deleted = response.data;
    await this.delete(deleted);
    return new Response(deleted);
  }

  async get(params = {}) {
    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativeOverrides(
      this.http,
      nativeOverridesQueryFromFilter(filter),
    );
    return new Response(nativeResponse.overrides, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(params = {}) {
    const filter = filterFromCommandParams(params).all();
    const overrides = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; overrides.length < total; page += 1) {
      const nativeResponse = await fetchNativeOverrides(this.http, {
        ...nativeOverridesQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      overrides.push(...nativeResponse.overrides);
      total = nativeResponse.page.total;
      if (nativeResponse.overrides.length === 0) {
        break;
      }
    }

    return new Response(
      overrides,
      nativeCollectionMeta(
        filter,
        overrides,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }
}

registerCommand('override', OverrideCommand);
registerCommand('overrides', OverridesCommand);

export {OverrideCommand, OverridesCommand};

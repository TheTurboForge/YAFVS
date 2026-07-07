/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand from 'gmp/commands/entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import {type XmlResponseData} from 'gmp/http/transform/fast-xml';
import logger from 'gmp/log';
import type {Element} from 'gmp/models/model';
import ReportConfig from 'gmp/models/report-config';
import {
  cloneNativeReportConfig,
  createNativeReportConfig,
  deleteNativeReportConfig,
  exportNativeReportConfigMetadata,
  patchNativeReportConfig,
  type NativeReportConfigCreateRequest,
  type NativeReportConfigPatchRequest,
} from 'gmp/native-api/report-configs';
import {parseYesNo} from 'gmp/parser';
import {isArray} from 'gmp/utils/identity';

type ReportConfigParamValue =
  | string
  | number
  | boolean
  | Array<string | number | boolean>;

interface ReportConfigCreateArgs {
  comment?: string;
  name: string;
  reportFormatId: string;
  params?: Record<string, ReportConfigParamValue>;
  paramsUsingDefault?: Record<string, string | number | boolean | undefined>;
  paramTypes?: Record<string, string>;
}

interface ReportConfigSaveArgs {
  id: string;
  comment?: string;
  name: string;
  params?: Record<string, ReportConfigParamValue>;
  paramsUsingDefault?: Record<string, string | number | boolean | undefined>;
  paramTypes?: Record<string, string>;
}

interface ReportConfigResponseData extends XmlResponseData {
  get_report_config?: {
    get_report_configs_response?: {
      report_config?: Element;
    };
  };
}

const log = logger.getLogger('gmp.commands.reportconfigs');

const reportConfigParamValueToString = (
  value: ReportConfigParamValue,
  paramType: string | undefined,
): string => {
  if (isArray(value)) {
    if (paramType === 'report_format_list') {
      return value.map(String).join(',');
    }
    return JSON.stringify(value);
  }
  return String(value);
};

const nativeReportConfigCreateRequestFromCommand = ({
  comment,
  name,
  reportFormatId,
  params = {},
  paramsUsingDefault = {},
  paramTypes = {},
}: ReportConfigCreateArgs): NativeReportConfigCreateRequest => ({
  name,
  report_format_id: reportFormatId,
  ...(comment !== undefined ? {comment} : {}),
  params: Object.entries(params)
    .filter(([paramName]) => !parseYesNo(paramsUsingDefault[paramName]))
    .map(([paramName, value]) => ({
      name: paramName,
      value: reportConfigParamValueToString(value, paramTypes[paramName]),
    })),
});

const hasNativeDefaultParam = (
  paramsUsingDefault: Record<string, string | number | boolean | undefined>,
): boolean =>
  Object.values(paramsUsingDefault).some(value => parseYesNo(value));

const haveSameKeys = (
  left?: Record<string, unknown>,
  right?: Record<string, unknown>,
): boolean => {
  const leftKeys = Object.keys(left ?? {}).sort();
  const rightKeys = Object.keys(right ?? {}).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index])
  );
};

const hasCompleteNativeParamState = ({
  params,
  paramsUsingDefault,
  paramTypes,
}: ReportConfigSaveArgs): boolean =>
  params !== undefined &&
  paramsUsingDefault !== undefined &&
  paramTypes !== undefined &&
  haveSameKeys(params, paramsUsingDefault) &&
  haveSameKeys(params, paramTypes);

const canUseNativeReportConfigPatch = (args: ReportConfigSaveArgs): boolean => {
  const paramsUsingDefault = args.paramsUsingDefault ?? {};
  return (
    !hasNativeDefaultParam(paramsUsingDefault) ||
    hasCompleteNativeParamState(args)
  );
};

const nativeReportConfigPatchRequestFromCommand = (
  args: ReportConfigSaveArgs,
): NativeReportConfigPatchRequest => {
  const {
    comment,
    name,
    params,
    paramsUsingDefault = {},
    paramTypes = {},
  } = args;
  const paramEntries = Object.entries(params ?? {}).filter(
    ([paramName]) => !parseYesNo(paramsUsingDefault[paramName]),
  );
  return {
    name,
    ...(comment !== undefined ? {comment} : {}),
    ...(params !== undefined
      ? {
          params: paramEntries.map(([paramName, value]) => ({
            name: paramName,
            value: reportConfigParamValueToString(value, paramTypes[paramName]),
          })),
        }
      : {}),
  };
};

export class ReportConfigCommand extends EntityCommand<ReportConfig> {
  constructor(http: Http) {
    super(http, 'report_config', ReportConfig);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeReportConfigMetadata(this.http, id);
  }

  async create(args: ReportConfigCreateArgs) {
    const {
      comment,
      name,
      reportFormatId,
      params = {},
      paramsUsingDefault = {},
      paramTypes = {},
    } = args;

    const data = {
      cmd: 'create_report_config',
      name,
      comment,
      report_format_id: reportFormatId,
    };

    for (const prefName in params) {
      let value = params[prefName];
      if (isArray(value)) {
        if (paramTypes[prefName] === 'report_format_list') {
          value = value.map(String).join(',');
        } else {
          value = JSON.stringify(value);
        }
      }
      data['param:' + prefName] = value;
    }

    for (const param_name in paramsUsingDefault) {
      if (paramsUsingDefault[param_name]) {
        data['param_using_default:' + param_name] = parseYesNo(
          paramsUsingDefault[param_name],
        );
      }
    }

    if (canUseNativeApi(this.http)) {
      return createNativeReportConfig(
        this.http,
        nativeReportConfigCreateRequestFromCommand(args),
      );
    }

    log.debug('Creating new report config', args);
    return this.action(data);
  }

  async save(args: ReportConfigSaveArgs) {
    const {
      id,
      comment,
      name,
      params = {},
      paramsUsingDefault = {},
      paramTypes = {},
    } = args;

    if (canUseNativeApi(this.http) && canUseNativeReportConfigPatch(args)) {
      return patchNativeReportConfig(
        this.http,
        id,
        nativeReportConfigPatchRequestFromCommand(args),
      );
    }

    const data = {
      cmd: 'save_report_config',
      id,
      name,
      comment,
    };

    for (const paramName in paramsUsingDefault) {
      if (paramsUsingDefault[paramName]) {
        data['param_using_default:' + paramName] = parseYesNo(
          paramsUsingDefault[paramName],
        );
      }
    }

    for (const prefName in params) {
      let value = params[prefName];
      if (isArray(value)) {
        if (paramTypes[prefName] === 'report_format_list') {
          value = value.map(String).join(',');
        } else {
          value = JSON.stringify(value);
        }
      }
      data['param:' + prefName] = value;
    }

    log.debug('Saving report config', args, data);
    return this.action(data);
  }

  getElementFromRoot(root: XmlResponseData) {
    return (
      (root as ReportConfigResponseData).get_report_config
        ?.get_report_configs_response?.report_config ?? {}
    );
  }

  async clone({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      try {
        return await cloneNativeReportConfig(this.http, id);
      } catch (error) {
        log.debug(
          'Native report config clone failed, falling back to GMP',
          error,
        );
      }
    }
    return super.clone({id});
  }

  async delete({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      await deleteNativeReportConfig(this.http, id);
      return;
    }
    return super.delete({id});
  }
}

export default ReportConfigCommand;

/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand from 'gmp/commands/entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {type XmlResponseData} from 'gmp/http/transform/fast-xml';
import type {Element} from 'gmp/models/model';
import ReportConfig from 'gmp/models/report-config';
import {
  cloneNativeReportConfig,
  createNativeReportConfig,
  deleteNativeReportConfig,
  exportNativeReportConfigMetadata,
  fetchNativeReportConfig,
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

const hasNativeParamDefaultState = (
  paramsUsingDefault: Record<string, string | number | boolean | undefined>,
): boolean => Object.keys(paramsUsingDefault).length > 0;

const hasCompleteNativeParamState = ({
  params = {},
  paramsUsingDefault = {},
}: ReportConfigSaveArgs): boolean =>
  Object.entries(paramsUsingDefault).every(
    ([paramName, usingDefault]) =>
      parseYesNo(usingDefault) || params[paramName] !== undefined,
  );

const canUseNativeReportConfigPatch = (args: ReportConfigSaveArgs): boolean => {
  const paramsUsingDefault = args.paramsUsingDefault ?? {};
  return (
    !hasNativeParamDefaultState(paramsUsingDefault) ||
    hasCompleteNativeParamState(args)
  );
};

const completeSparseNativeReportConfigPatch = async (
  http: Http,
  args: ReportConfigSaveArgs,
): Promise<ReportConfigSaveArgs | undefined> => {
  if (canUseNativeReportConfigPatch(args)) {
    return args;
  }

  const current = await fetchNativeReportConfig(http, args.id);
  const params = {...(args.params ?? {})};
  const paramTypes = {...(args.paramTypes ?? {})};

  for (const [paramName, usingDefault] of Object.entries(
    args.paramsUsingDefault ?? {},
  )) {
    if (parseYesNo(usingDefault) || params[paramName] !== undefined) {
      continue;
    }
    const currentParam = current.params.find(param => param.name === paramName);
    if (currentParam?.value === undefined) {
      return undefined;
    }
    params[paramName] = currentParam.value;
    if (currentParam.type !== undefined) {
      paramTypes[paramName] = currentParam.type;
    }
  }

  return {
    ...args,
    params,
    paramTypes,
  };
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

  async get({id}: EntityCommandParams) {
    return new Response(await fetchNativeReportConfig(this.http, id));
  }

  async create(args: ReportConfigCreateArgs) {
    return createNativeReportConfig(
      this.http,
      nativeReportConfigCreateRequestFromCommand(args),
    );
  }

  async save(args: ReportConfigSaveArgs) {
    const nativeArgs = await completeSparseNativeReportConfigPatch(
      this.http,
      args,
    );
    if (nativeArgs !== undefined) {
      return patchNativeReportConfig(
        this.http,
        args.id,
        nativeReportConfigPatchRequestFromCommand(nativeArgs),
      );
    }
    throw new Error(
      'Native report config save requires complete non-default parameter values',
    );
  }

  getElementFromRoot(root: XmlResponseData) {
    return (
      (root as ReportConfigResponseData).get_report_config
        ?.get_report_configs_response?.report_config ?? {}
    );
  }

  async clone({id}: EntityCommandParams) {
    return await cloneNativeReportConfig(this.http, id);
  }

  async delete({id}: EntityCommandParams) {
    await deleteNativeReportConfig(this.http, id);
  }
}

export default ReportConfigCommand;

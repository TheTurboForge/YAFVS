/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {type Date} from 'gmp/models/date';
import Model, {type ModelElement, type ModelProperties} from 'gmp/models/model';
import {
  parseDate,
  parseYesNo,
  YES_VALUE,
  parseBoolean,
  type YesNo,
  parseInt,
} from 'gmp/parser';
import {filter, map} from 'gmp/utils/array';
import {isDefined, isObject} from 'gmp/utils/identity';
import {isEmpty} from 'gmp/utils/string';

interface ParamObjectValueElement {
  __text?: string | number | boolean;
  _using_default?: YesNo | '0' | '1';
}

export interface ParamElement {
  default?:
    | string
    | number
    | boolean
    | string[]
    | {__text: string | number | boolean}
    | {report_format: ModelElement | ModelElement[]};
  name?: string;
  options?: {
    option: string | string[];
  };
  type?:
    | string
    | {
        __text?: string;
        max?: number;
        min?: number;
      };
  value?:
    | string
    | number
    | boolean
    | string[]
    | ParamObjectValueElement
    | {report_format: ModelElement | ModelElement[]};
}

type ParamValue = string | number | boolean | string[];
interface ParamOption {
  value: string;
  name: string;
}
interface ParamLabels {
  [key: string]: string | undefined;
}
type ParamType =
  | 'report_format_list'
  | 'multi_selection'
  | 'integer'
  | 'boolean'
  | 'text';

interface ReportFormatElement extends ModelElement {
  alerts?: {
    alert: ModelElement | ModelElement[];
  };
  configurable?: YesNo;
  content_type?: string;
  deprecated?: boolean;
  extension?: string;
  invisible_alerts?: number;
  param?: ParamElement | ParamElement[];
  predefined?: YesNo;
  report_type?: string;
  signature?: string;
  trust?: {
    __text?: string;
    time?: string;
  };
}

interface Trust {
  value?: string;
  time?: Date;
}

interface ReportFormatProperties extends ModelProperties {
  alerts?: Model[];
  configurable?: boolean;
  content_type?: string;
  deprecated?: boolean;
  extension?: string;
  invisible_alerts?: number;
  params?: Param[];
  predefined?: boolean;
  report_type?: string;
  trust?: Trust;
}

const getValue = <TValue>(val?: {__text?: TValue} | TValue): TValue => {
  // @ts-expect-error
  return isObject(val) ? val.__text : val;
};

export class Param {
  readonly default?: ParamValue;
  readonly defaultLabels?: ParamLabels;
  readonly max?: number;
  readonly min?: number;
  readonly name?: string;
  readonly options: ParamOption[];
  readonly type?: ParamType;
  readonly value?: ParamValue;
  readonly valueUsingDefault?: boolean;
  readonly valueLabels?: ParamLabels;

  constructor({name, type, value, options, ...other}: ParamElement) {
    this.name = name;
    this.max = isObject(type) ? parseInt(type?.max) : undefined;
    this.min = isObject(type) ? parseInt(type?.min) : undefined;
    this.type = getValue(type) as ParamType;
    this.valueUsingDefault =
      isObject(value) &&
      isDefined((value as ParamObjectValueElement)?._using_default)
        ? parseBoolean((value as ParamObjectValueElement)?._using_default)
        : undefined;

    if (isObject(options)) {
      this.options = map(options.option, opt => {
        return {
          value: opt,
          name: opt,
        };
      });
    } else {
      this.options = [];
    }

    if (this.type === 'report_format_list') {
      let {report_format: reportFormats = []} = value as {
        report_format: ModelElement[];
      };
      let {report_format: defaultReportFormats = []} = other.default as {
        report_format: ModelElement[];
      };
      reportFormats = filter(reportFormats, (format: ModelElement) =>
        isDefined(format._id),
      );
      defaultReportFormats = filter(
        defaultReportFormats,
        (format: ModelElement) => isDefined(format._id),
      );
      this.value = map(reportFormats, format => format._id as string);
      this.default = map(defaultReportFormats, format => format._id as string);

      this.valueLabels = reportFormats.reduce<
        Record<string, string | undefined>
      >(
        (acc, format) => ({
          ...acc,
          [format._id as string]: format.name,
        }),
        {},
      );
      this.defaultLabels = defaultReportFormats.reduce<
        Record<string, string | undefined>
      >(
        (acc, format) => ({
          ...acc,
          [format._id as string]: format.name,
        }),
        {},
      );
    } else if (this.type === 'multi_selection') {
      this.value = JSON.parse(getValue(value as string)) as string[];
      this.default = JSON.parse(getValue(other.default as string)) as string[];
    } else if (this.type === 'integer') {
      this.value = parseInt(getValue(value as number));
      this.default = parseInt(getValue(other.default as number));
    } else if (this.type === 'boolean') {
      this.value = parseBoolean(getValue(value as string));
      this.default = parseBoolean(getValue(other.default as string));
    } else {
      this.value = getValue(value as string);
      this.default = getValue(other.default as string);
    }
  }
}

class ReportFormat extends Model {
  static readonly entityType = 'reportformat';

  readonly alerts: Model[];
  readonly configurable?: boolean;
  readonly content_type?: string;
  readonly deprecated?: boolean;
  readonly extension?: string;
  readonly invisible_alerts?: number;
  readonly params: Param[];
  readonly predefined?: boolean;
  readonly report_type?: string;
  readonly trust?: Trust;

  constructor({
    alerts = [],
    configurable,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    content_type,
    deprecated,
    extension,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    invisible_alerts,
    params = [],
    predefined,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    report_type,
    trust,
    ...properties
  }: ReportFormatProperties = {}) {
    super(properties);

    this.alerts = alerts;
    this.configurable = configurable;
    this.content_type = content_type;
    this.deprecated = deprecated;
    this.extension = extension;
    this.invisible_alerts = invisible_alerts;
    this.params = params;
    this.predefined = predefined;
    this.report_type = report_type;
    this.trust = trust;
  }

  static fromElement(element: ReportFormatElement = {}): ReportFormat {
    return new ReportFormat(this.parseElement(element));
  }

  static parseElement(
    element: ReportFormatElement = {},
  ): ReportFormatProperties {
    const ret = super.parseElement(element) as ReportFormatProperties;

    if (isDefined(element.trust)) {
      ret.trust = {
        value: getValue(element.trust),
        time: isEmpty(element.trust.time)
          ? undefined
          : parseDate(element.trust.time),
      };
    }

    ret.params = map(element.param, param => {
      return new Param(param);
    });

    ret.alerts = map(element.alerts?.alert, alert =>
      Model.fromElement(alert, 'alert'),
    );

    ret.invisible_alerts = parseInt(element.invisible_alerts);
    ret.active = isDefined(element.active)
      ? parseYesNo(element.active)
      : undefined;
    ret.configurable = isDefined(element.configurable)
      ? parseBoolean(element.configurable)
      : undefined;
    ret.deprecated = isDefined(element.deprecated)
      ? element.deprecated === true
      : undefined;
    ret.predefined = isDefined(element.predefined)
      ? parseBoolean(element.predefined)
      : undefined;

    return ret;
  }

  isActive() {
    return this.active === YES_VALUE;
  }

  isTrusted() {
    return this.trust?.value === 'yes';
  }
}

export default ReportFormat;

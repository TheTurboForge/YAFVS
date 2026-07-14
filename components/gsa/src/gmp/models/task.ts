/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {_l} from 'gmp/locale/lang';
import {type Date, type Duration} from 'gmp/models/date';
import {type EntityModelPermissionElement} from 'gmp/models/entity-model';
import Model, {type ModelElement, type ModelProperties} from 'gmp/models/model';
import Scanner, {type ScannerType} from 'gmp/models/scanner';
import Schedule from 'gmp/models/schedule';
import {
  parseInt,
  parseProgressElement,
  parseYesNo,
  parseYes,
  parseDuration,
  YES_VALUE,
  type YesNo,
  parseToString,
  parseDate,
  parseSeverity,
} from 'gmp/parser';
import {map} from 'gmp/utils/array';
import {isDefined, isArray, isString} from 'gmp/utils/identity';
import {isEmpty} from 'gmp/utils/string';

export type TaskHostsOrdering =
  | typeof HOSTS_ORDERING_SEQUENTIAL
  | typeof HOSTS_ORDERING_RANDOM
  | typeof HOSTS_ORDERING_REVERSE;
export type TaskStatus = (typeof TASK_STATUS)[keyof typeof TASK_STATUS];
export type TaskTrend = 'up' | 'down' | 'more' | 'less' | 'same';
export type TaskAutoDelete = typeof AUTO_DELETE_KEEP | typeof AUTO_DELETE_NO;

interface TaskPreferenceElement {
  name?: string;
  scanner_name: string;
  value?: string | number;
}

interface TaskAlertElement {
  _id?: string;
  name?: string;
}

export interface TaskElement extends ModelElement {
  alert?: TaskAlertElement | TaskAlertElement[];
  alterable?: YesNo;
  average_duration?: number;
  config?: {
    _id?: string;
    name?: string;
    trash?: YesNo;
  };
  current_report?: {
    // only available for a running task
    report?: {
      _id?: string;
      timestamp?: string;
      scan_start?: string;
      scan_end?: string;
    };
  };
  hosts_ordering?: TaskHostsOrdering;
  last_report?: {
    // Only available for tasks with finished scans
    report?: {
      _id?: string;
      // get_tasks result_counts are different then compared to get_reports
      result_count?: {
        false_positive?: number;
        hole?: {
          __text?: number;
          _deprecated: '1';
        };
        info?: {
          __text?: number;
          _deprecated: '1';
        };
        high?: number;
        log?: number;
        low?: number;
        medium?: number;
        warning?: {
          __text?: number;
          _deprecated: '1';
        };
      };
      scan_end?: string;
      scan_start?: string;
      severity?: number;
      timestamp?: string;
    };
  };
  preferences?: {
    preference?: TaskPreferenceElement | TaskPreferenceElement[];
  };
  progress?: number | {__text?: number};
  report_count?: {
    __text?: number;
    finished?: number;
  };
  result_count?: number;
  scanner?: {
    _id?: string;
    name?: string;
    trash?: YesNo;
    type?: ScannerType;
  };
  schedule?: {
    _id?: string;
    icalendar?: string;
    name?: string;
    timezone?: string;
    trash?: YesNo;
    permissions?: {
      permission: EntityModelPermissionElement | EntityModelPermissionElement[];
    };
  };
  schedule_periods?: number;
  slave?: {
    _id?: string;
  };
  status?: TaskStatus;
  target?: {
    _id?: string;
    name?: string;
    trash?: YesNo;
  };
  trend?: TaskTrend;
  usage_type?: string;
}

export interface ReportCount {
  total?: number;
  finished?: number;
}

export interface TaskPreferences {
  [key: string]: {
    value: string | number;
    name?: string;
  };
}

export interface TaskSlave {
  id?: string;
}

export interface TaskReport {
  entityType: 'report';
  id: string;
  result_count?: {
    high?: number;
    medium?: number;
    low?: number;
    log?: number;
    false_positive?: number;
  };
  scan_end?: Date;
  scan_start?: Date;
  severity?: number;
  timestamp?: Date;
}

export interface TaskProperties extends ModelProperties {
  alerts?: Model[];
  alterable?: YesNo;
  average_duration?: Duration;
  config?: Model;
  current_report?: TaskReport;
  hosts_ordering?: TaskHostsOrdering;
  last_report?: TaskReport;
  preferences?: TaskPreferences;
  progress?: number;
  report_count?: ReportCount;
  result_count?: number;
  scanner?: Scanner;
  schedule?: Schedule;
  schedule_periods?: number;
  slave?: TaskSlave;
  status?: TaskStatus;
  target?: Model;
  trend?: TaskTrend;
  // from preferences
  apply_overrides?: YesNo;
  auto_delete_data?: number;
  auto_delete?: TaskAutoDelete;
  in_assets?: YesNo;
  max_checks?: number;
  max_hosts?: number;
  min_qod?: number;
  acceptInvalidCerts?: boolean;
  registryAllowInsecure?: boolean;
  usageType?: TaskUsageType;
}

export type TaskUsageType = (typeof USAGE_TYPE)[keyof typeof USAGE_TYPE];

export const AUTO_DELETE_KEEP = 'keep';
export const AUTO_DELETE_NO = 'no';
export const AUTO_DELETE_KEEP_DEFAULT_VALUE = 10;

export const HOSTS_ORDERING_SEQUENTIAL = 'sequential';
export const HOSTS_ORDERING_RANDOM = 'random';
export const HOSTS_ORDERING_REVERSE = 'reverse';

export const DEFAULT_MAX_CHECKS = 4;
export const DEFAULT_MAX_HOSTS = 20;
export const DEFAULT_MIN_QOD = 70;

export const TASK_STATUS = {
  queued: 'Queued',
  running: 'Running',
  stoprequested: 'Stop Requested',
  deleterequested: 'Delete Requested',
  ultimatedeleterequested: 'Ultimate Delete Requested',
  requested: 'Requested',
  stopped: 'Stopped',
  new: 'New',
  interrupted: 'Interrupted',
  processing: 'Processing',
  done: 'Done',
  unknown: 'Unknown',
} as const;

export const USAGE_TYPE = {
  scan: 'scan',
} as const;

const TASK_STATUS_TRANSLATIONS = {
  Running: _l('Running'),
  'Stop Requested': _l('Stop Requested'),
  'Delete Requested': _l('Delete Requested'),
  'Ultimate Delete Requested': _l('Ultimate Delete Requested'),
  Requested: _l('Requested'),
  Stopped: _l('Stopped'),
  New: _l('New'),
  Interrupted: _l('Interrupted'),
  Done: _l('Done'),
  Queued: _l('Queued'),
  Processing: _l('Processing'),
  Unknown: _l('Unknown'),
} as const;

export const getTranslatableTaskStatus = (status: TaskStatus) =>
  `${TASK_STATUS_TRANSLATIONS[status]}`;

export const isActive = (status?: TaskStatus) =>
  status === TASK_STATUS.running ||
  status === TASK_STATUS.stoprequested ||
  status === TASK_STATUS.deleterequested ||
  status === TASK_STATUS.ultimatedeleterequested ||
  status === TASK_STATUS.requested ||
  status === TASK_STATUS.queued ||
  status === TASK_STATUS.processing;

class Task extends Model {
  static readonly entityType = 'task';

  readonly alerts: Model[];
  readonly alterable?: YesNo;
  readonly apply_overrides?: YesNo;
  readonly auto_delete_data?: number;
  readonly auto_delete?: TaskAutoDelete;
  readonly average_duration?: Duration;
  readonly config?: Model;
  readonly current_report?: TaskReport;
  readonly hosts_ordering?: TaskHostsOrdering;
  readonly in_assets?: YesNo;
  readonly last_report?: TaskReport;
  readonly max_checks?: number;
  readonly max_hosts?: number;
  readonly min_qod?: number;
  readonly acceptInvalidCerts?: boolean;
  readonly registryAllowInsecure?: boolean;
  readonly preferences: TaskPreferences;
  readonly progress?: number;
  readonly report_count?: ReportCount;
  readonly result_count?: number;
  readonly scanner?: Scanner;
  readonly schedule_periods?: number;
  readonly schedule?: Schedule;
  readonly slave?: TaskSlave;
  readonly status: TaskStatus;
  readonly target?: Model;
  readonly trend?: TaskTrend;
  readonly usageType: TaskUsageType;

  constructor({
    alerts = [],
    alterable,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    apply_overrides,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    auto_delete_data,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    auto_delete,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    average_duration,
    config,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    current_report,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    hosts_ordering,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    in_assets,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    last_report,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    max_checks,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    max_hosts,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    min_qod,
    acceptInvalidCerts,
    registryAllowInsecure,
    preferences = {},
    progress,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    report_count,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    result_count,
    scanner,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    schedule_periods,
    schedule,
    slave,
    status = TASK_STATUS.unknown,
    target,
    trend,
    usageType = USAGE_TYPE.scan,
    ...properties
  }: TaskProperties = {}) {
    super(properties);

    this.alerts = alerts;
    this.alterable = alterable;
    this.apply_overrides = apply_overrides;
    this.auto_delete_data = auto_delete_data;
    this.auto_delete = auto_delete;
    this.average_duration = average_duration;
    this.config = config;
    this.current_report = current_report;
    this.hosts_ordering = hosts_ordering;
    this.in_assets = in_assets;
    this.last_report = last_report;
    this.max_checks = max_checks;
    this.max_hosts = max_hosts;
    this.min_qod = min_qod;
    this.acceptInvalidCerts = acceptInvalidCerts;
    this.registryAllowInsecure = registryAllowInsecure;
    this.preferences = preferences;
    this.progress = progress;
    this.report_count = report_count;
    this.result_count = result_count;
    this.scanner = scanner;
    this.schedule_periods = schedule_periods;
    this.schedule = schedule;
    this.slave = slave;
    this.status = status;
    this.target = target;
    this.trend = trend;
    this.usageType = usageType;
  }

  static fromElement(element?: TaskElement): Task {
    return new Task(this.parseElement(element));
  }

  static parseElement(element: TaskElement = {}): TaskProperties {
    const copy = super.parseElement(element) as TaskProperties;

    const usageType = (element.usage_type ?? USAGE_TYPE.scan) as TaskUsageType;

    if (!Object.values(USAGE_TYPE).includes(usageType)) {
      throw new Error("Task.parseElement: usage_type must be 'scan'");
    }

    copy.usageType = usageType;

    const {report_count} = element;

    if (isDefined(report_count)) {
      copy.report_count = {
        total: parseInt(report_count.__text),
        finished: parseInt(report_count.finished),
      };
    }

    copy.alterable = isDefined(element.alterable)
      ? parseYesNo(element.alterable)
      : undefined;
    copy.result_count = parseInt(element.result_count);
    copy.trend = parseToString(element.trend) as TaskTrend | undefined;

    if (!isEmpty(element.last_report?.report?._id)) {
      const lastReport: TaskReport = {
        entityType: 'report',
        id: element.last_report?.report?._id as string,
        timestamp: parseDate(element.last_report?.report?.timestamp),
        scan_start: parseDate(element.last_report?.report?.scan_start),
        scan_end: parseDate(element.last_report?.report?.scan_end),
        severity: parseSeverity(element.last_report?.report?.severity),
      };
      if (isDefined(element.last_report?.report?.result_count)) {
        lastReport.result_count = {
          high: parseInt(element.last_report?.report?.result_count?.high),
          medium: parseInt(element.last_report?.report?.result_count?.medium),
          low: parseInt(element.last_report?.report?.result_count?.low),
          log: parseInt(element.last_report?.report?.result_count?.log),
          false_positive: parseInt(
            element.last_report?.report?.result_count?.false_positive,
          ),
        };
      }
      copy.last_report = lastReport;
    }
    copy.current_report = isEmpty(element.current_report?.report?._id)
      ? undefined
      : {
          id: element.current_report?.report?._id as string,
          entityType: 'report',
          timestamp: parseDate(element.current_report?.report?.timestamp),
          scan_start: parseDate(element.current_report?.report?.scan_start),
          scan_end: parseDate(element.current_report?.report?.scan_end),
        };

    copy.config = isEmpty(element.config?._id)
      ? undefined
      : Model.fromElement(element.config, 'scanconfig');
    copy.target = isEmpty(element.target?._id)
      ? undefined
      : Model.fromElement(element.target, 'target');
    // slave isn't really an entity type but it has an id
    copy.slave = isEmpty(element.slave?._id)
      ? undefined
      : {id: element.slave?._id};
    copy.alerts = map(element.alert, alert =>
      Model.fromElement(alert, 'alert'),
    );
    copy.scanner = isEmpty(element.scanner?._id)
      ? undefined
      : Scanner.fromElement(element.scanner);
    copy.schedule = isEmpty(element.schedule?._id)
      ? undefined
      : Schedule.fromElement(element.schedule);
    copy.schedule_periods = parseInt(element.schedule_periods);
    copy.hosts_ordering = element.hosts_ordering;

    // it seems element.progress is just a number now, but keep the element parsing as a fallback
    // maybe some other code path relies on the other format
    copy.progress = isDefined(element.progress)
      ? parseProgressElement(element.progress)
      : undefined;

    const prefs = {};

    if (isArray(element.preferences?.preference)) {
      for (const pref of element.preferences.preference) {
        switch (pref.scanner_name) {
          case 'in_assets':
            copy.in_assets = parseYes(pref.value as string);
            break;
          case 'assets_apply_overrides':
            copy.apply_overrides = parseYes(pref.value as string);
            break;
          case 'assets_min_qod':
            copy.min_qod = parseInt(pref.value);
            break;
          case 'auto_delete':
            copy.auto_delete =
              pref.value === AUTO_DELETE_KEEP
                ? AUTO_DELETE_KEEP
                : AUTO_DELETE_NO;
            break;
          case 'auto_delete_data': {
            const value = parseInt(pref.value);
            copy.auto_delete_data =
              value === 0 ? AUTO_DELETE_KEEP_DEFAULT_VALUE : value;
            break;
          }
          case 'max_hosts':
          case 'max_checks':
            copy[pref.scanner_name] = parseInt(pref.value);
            break;
          case 'accept_invalid_certs':
            copy.acceptInvalidCerts = parseYesNo(pref.value) === YES_VALUE;
            break;
          case 'registry_allow_insecure':
            copy.registryAllowInsecure = parseYesNo(pref.value) === YES_VALUE;
            break;
          default:
            prefs[pref.scanner_name] = {value: pref.value, name: pref.name};
            break;
        }
      }
    }

    copy.preferences = prefs;

    copy.average_duration = parseDuration(element.average_duration);

    return copy;
  }
  isActive() {
    return isActive(this.status);
  }

  isRunning() {
    return this.status === TASK_STATUS.running;
  }

  isStopped() {
    return this.status === TASK_STATUS.stopped;
  }

  isInterrupted() {
    return this.status === TASK_STATUS.interrupted;
  }

  isQueued() {
    return this.status === TASK_STATUS.queued;
  }

  isNew() {
    return this.status === TASK_STATUS.new;
  }

  isChangeable() {
    return true;
  }

  isAlterable() {
    return true;
  }
}

export default Task;

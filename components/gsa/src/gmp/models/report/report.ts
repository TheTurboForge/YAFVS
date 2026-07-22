/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 * SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import CollectionCounts from 'gmp/collection/collection-counts';
import {type CollectionList, parseFilter} from 'gmp/collection/parser';
import {type Date} from 'gmp/models/date';
import Filter, {type FilterKeyword} from 'gmp/models/filter';
import Model, {type ModelElement, type ModelProperties} from 'gmp/models/model';
import type ReportApp from 'gmp/models/report/app';
import type ReportHost from 'gmp/models/report/host';
import type ReportOperatingSystem from 'gmp/models/report/os';
import {
  parseApps,
  parseCves,
  parseErrors,
  parseHosts,
  parseOperatingSystems,
  parsePorts,
  parseResults,
  parseTlsCertificates,
  type ReportActiveCve,
  type ReportResultsElement,
  type CountElement,
  type TlsCertificatesElement,
  type ReportResultCountElement,
  type PortsElement,
  type ReportHostElement,
  type ErrorsElement,
  type ReportError,
} from 'gmp/models/report/parser';
import type ReportPort from 'gmp/models/report/port';
import ReportTask from 'gmp/models/report/task';
import type ReportTLSCertificate from 'gmp/models/report/tls-certificate';
import type Result from 'gmp/models/result';
import {type TaskStatus} from 'gmp/models/task';
import {parseSeverity, parseDate, type YesNo} from 'gmp/parser';
import {isDefined} from 'gmp/utils/identity';

export type ReportType = 'scan' | 'assets';

interface ReportFiltersElement {
  _id?: string;
  filter?: string[];
  keywords?: {
    keyword?: FilterKeyword | FilterKeyword[];
  };
  term?: string;
}

export interface ReportReportTaskElement {
  _id?: string;
  comment?: string;
  name?: string;
  progress?: number;
  target?: {
    _id?: string;
    comment?: string;
    name?: string;
    trash?: YesNo;
  };
}

export interface ReportReportElement extends ModelElement {
  _type?: ReportType;
  apps?: CountElement;
  errors?: ErrorsElement;
  filters?: ReportFiltersElement;
  gmp?: {
    version?: string;
  };
  host?: ReportHostElement | ReportHostElement[];
  hosts?: CountElement;
  ports?: PortsElement;
  os?: CountElement;
  result_count?: ReportResultCountElement;
  results?: ReportResultsElement; // only present if details=1
  scan_end?: string;
  scan_start?: string;
  scan_run_status?: string;
  severity?: {
    filtered?: number;
    full?: number;
  };
  sort?: {
    field?: {
      __text?: string;
      order?: 'descending' | 'ascending';
    };
  };
  ssl_certs?: CountElement;
  task?: ReportReportTaskElement;
  timestamp?: string;
  timezone?: string;
  timezone_abbrev?: string;
  tls_certificates?: TlsCertificatesElement;
  vulns?: CountElement;
}

interface ReportReportSeverity {
  filtered?: number;
  full?: number;
}

interface ReportResultCounts {
  filtered?: number;
  full?: number;
  critical?: {
    filtered?: number;
    full?: number;
  };
  high?: {
    filtered?: number;
    full?: number;
  };
  medium?: {
    filtered?: number;
    full?: number;
  };
  low?: {
    filtered?: number;
    full?: number;
  };
  log?: {
    filtered?: number;
    full?: number;
  };
  false_positive?: {
    filtered?: number;
    full?: number;
  };
}

interface ReportReportProperties extends ModelProperties {
  applications?: CollectionList<ReportApp>;
  cves?: CollectionList<ReportActiveCve>;
  errors?: CollectionList<ReportError>;
  filter?: Filter;
  hosts?: CollectionList<ReportHost>;
  operatingsystems?: CollectionList<ReportOperatingSystem>;
  ports?: CollectionList<ReportPort>;
  report_type?: ReportType;
  results?: CollectionList<Result>;
  result_count?: ReportResultCounts;
  scan_end?: Date;
  scan_run_status?: TaskStatus;
  scan_start?: Date;
  severity?: ReportReportSeverity;
  task?: ReportTask;
  timezone?: string;
  timezone_abbrev?: string;
  tlsCertificates?: CollectionList<ReportTLSCertificate>;
  vulns?: CollectionCounts;
}

class ReportReport extends Model {
  static readonly entityType = 'report';

  readonly applications?: CollectionList<ReportApp>;
  readonly cves?: CollectionList<ReportActiveCve>;
  readonly errors?: CollectionList<ReportError>;
  readonly filter?: Filter;
  readonly hosts?: CollectionList<ReportHost>;
  readonly operatingsystems?: CollectionList<ReportOperatingSystem>;
  readonly ports?: CollectionList<ReportPort>;
  readonly report_type?: ReportType;
  readonly result_count?: ReportResultCounts;
  readonly results?: CollectionList<Result>;
  readonly scan_end?: Date;
  readonly scan_run_status?: TaskStatus;
  readonly scan_start?: Date;
  readonly severity?: ReportReportSeverity;
  readonly task?: ReportTask;
  readonly timezone?: string;
  readonly timezone_abbrev?: string;
  readonly tlsCertificates?: CollectionList<ReportTLSCertificate>;
  readonly vulns?: CollectionCounts;

  constructor({
    applications,
    cves,
    errors,
    filter,
    hosts,
    operatingsystems,
    ports,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    report_type,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    result_count,
    results,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    scan_end,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    scan_run_status,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    scan_start,
    severity,
    task,
    timezone,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    timezone_abbrev,
    tlsCertificates,
    vulns,
    ...properties
  }: ReportReportProperties = {}) {
    super(properties);

    this.applications = applications;
    this.cves = cves;
    this.errors = errors;
    this.filter = filter;
    this.hosts = hosts;
    this.operatingsystems = operatingsystems;
    this.ports = ports;
    this.report_type = report_type;
    this.result_count = result_count;
    this.results = results;
    this.scan_end = scan_end;
    this.scan_run_status = scan_run_status;
    this.scan_start = scan_start;
    this.severity = severity;
    this.task = task;
    this.timezone = timezone;
    this.timezone_abbrev = timezone_abbrev;
    this.tlsCertificates = tlsCertificates;
    this.vulns = vulns;
  }

  static fromElement(element?: ReportReportElement): ReportReport {
    return new ReportReport(this.parseElement(element));
  }

  static parseElement(
    element: ReportReportElement = {},
  ): ReportReportProperties {
    const copy = super.parseElement(element) as ReportReportProperties;

    const {severity, scan_start, scan_end, task} = element;

    const filter = isDefined(element.filters)
      ? parseFilter(element)
      : new Filter();
    copy.filter = filter;

    copy.report_type = element._type;

    copy.severity = isDefined(severity)
      ? {
          filtered: parseSeverity(severity.filtered),
          full: parseSeverity(severity.full),
        }
      : undefined;

    copy.task = ReportTask.fromElement(task);

    copy.results = parseResults(element);
    copy.hosts = parseHosts(element, filter);
    copy.tlsCertificates = parseTlsCertificates(element, filter);
    copy.applications = parseApps(element, filter);
    copy.operatingsystems = parseOperatingSystems(element, filter);
    copy.ports = parsePorts(element, filter);
    copy.cves = parseCves(element, filter);
    copy.errors = parseErrors(element, filter);
    copy.vulns = isDefined(element.vulns)
      ? new CollectionCounts({
          all: element.vulns.count,
          filtered: element.vulns.count,
          first: 1,
          length: element.vulns.count,
          rows: element.vulns.count,
        })
      : undefined;

    copy.scan_start = parseDate(scan_start);
    copy.scan_end = parseDate(scan_end);
    copy.scan_run_status = element.scan_run_status as TaskStatus;
    copy.timezone = element.timezone;
    copy.timezone_abbrev = element.timezone_abbrev;

    if (isDefined(element.result_count)) {
      copy.result_count = {
        filtered: element.result_count.filtered,
        full: element.result_count.full,
        critical: {
          filtered: element.result_count.critical?.filtered,
          full: element.result_count.critical?.full,
        },
        false_positive: {
          filtered: element.result_count.false_positive?.filtered,
          full: element.result_count.false_positive?.full,
        },
        high: {
          filtered: element.result_count.high?.filtered,
          full: element.result_count.high?.full,
        },
        log: {
          filtered: element.result_count.log?.filtered,
          full: element.result_count.log?.full,
        },
        low: {
          filtered: element.result_count.low?.filtered,
          full: element.result_count.low?.full,
        },
        medium: {
          filtered: element.result_count.medium?.filtered,
          full: element.result_count.medium?.full,
        },
      };
    }

    return copy;
  }
}

export default ReportReport;

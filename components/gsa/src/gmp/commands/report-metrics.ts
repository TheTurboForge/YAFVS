/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type {XmlResponseData} from 'gmp/http/transform/fast-xml';
import {isDefined} from 'gmp/utils/identity';

type XmlNode = Record<string, unknown>;

export interface ReportMetricsSummary {
  aliveSystemCount: number;
  totalSystemCvssLoad: number;
  averageSystemCvssLoad: number;
  vulnerabilityCount: number;
  authenticatedSystemCount: number;
  authenticationFailedSystemCount: number;
  noCredentialPathSystemCount: number;
  unknownAuthenticationSystemCount: number;
  authenticatedScanCoveragePercent: number;
}

export interface ReportMetricSystem {
  host: string;
  cvssLoad: number;
  maxCvss: number;
  vulnerabilityCount: number;
  authenticationState: string;
  sourceReportCount: number;
}

export interface ReportMetricVulnerability {
  nvtOid: string;
  name: string;
  cvssScore: number;
  affectedSystemCount: number;
  cvssLoad: number;
  averageContribution: number;
  sourceReportCount: number;
}

export interface ReportMetrics {
  id: string;
  summary: ReportMetricsSummary;
  systems: ReportMetricSystem[];
  vulnerabilities: ReportMetricVulnerability[];
}

const asArray = <T,>(value: T | T[] | undefined): T[] => {
  if (!isDefined(value)) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

const getNode = (node: unknown): XmlNode => {
  if (typeof node === 'object' && node !== null) {
    return node as XmlNode;
  }
  return {};
};

const text = (node: unknown, fallback = ''): string => {
  if (!isDefined(node)) {
    return fallback;
  }
  if (typeof node === 'string' || typeof node === 'number') {
    return String(node);
  }
  const data = getNode(node);
  if (isDefined(data.__text)) {
    return String(data.__text);
  }
  return fallback;
};

const numberValue = (node: unknown): number => {
  const value = Number.parseFloat(text(node, '0'));
  return Number.isFinite(value) ? value : 0;
};

const integerValue = (node: unknown): number => {
  const value = Number.parseInt(text(node, '0'), 10);
  return Number.isFinite(value) ? value : 0;
};

const idOf = (node: unknown): string => {
  const data = getNode(node);
  return text(data._id, text(data.id));
};

export const parseReportMetrics = (node: unknown): ReportMetrics => {
  const data = getNode(node);
  const summary = getNode(data.summary);
  const systems = getNode(data.systems);
  const vulnerabilities = getNode(data.vulnerabilities);

  return {
    id: idOf(data),
    summary: {
      aliveSystemCount: integerValue(summary.alive_system_count),
      totalSystemCvssLoad: numberValue(summary.total_system_cvss_load),
      averageSystemCvssLoad: numberValue(summary.average_system_cvss_load),
      vulnerabilityCount: integerValue(summary.vulnerability_count),
      authenticatedSystemCount: integerValue(summary.authenticated_system_count),
      authenticationFailedSystemCount: integerValue(summary.authentication_failed_system_count),
      noCredentialPathSystemCount: integerValue(summary.no_credential_path_system_count),
      unknownAuthenticationSystemCount: integerValue(summary.unknown_authentication_system_count),
      authenticatedScanCoveragePercent: numberValue(summary.authenticated_scan_coverage_percent),
    },
    systems: asArray(systems.system).map(system => {
      const item = getNode(system);
      return {
        host: text(item.host),
        cvssLoad: numberValue(item.cvss_load),
        maxCvss: numberValue(item.max_cvss),
        vulnerabilityCount: integerValue(item.vulnerability_count),
        authenticationState: text(item.authentication_state, 'unknown'),
        sourceReportCount: integerValue(item.source_report_count),
      };
    }),
    vulnerabilities: asArray(vulnerabilities.vulnerability).map(vulnerability => {
      const item = getNode(vulnerability);
      return {
        nvtOid: text(item.nvt_oid),
        name: text(item.name),
        cvssScore: numberValue(item.cvss_score),
        affectedSystemCount: integerValue(item.affected_system_count),
        cvssLoad: numberValue(item.cvss_load),
        averageContribution: numberValue(item.average_contribution),
        sourceReportCount: integerValue(item.source_report_count),
      };
    }),
  };
};

export const getMetricsNode = (
  root: XmlResponseData,
  commandName: 'get_report_metrics' | 'get_scope_report_metrics',
  nodeName: 'report_metrics' | 'scope_report_metrics',
) => {
  const command = getNode(root[commandName]);
  const response = getNode(command[`${commandName}_response`]);
  return response[nodeName];
};

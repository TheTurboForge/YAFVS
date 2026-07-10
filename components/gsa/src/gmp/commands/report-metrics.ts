/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

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

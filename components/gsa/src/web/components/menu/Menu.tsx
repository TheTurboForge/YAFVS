/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {AppNavigation} from '@greenbone/ui-lib';
import {
  Server,
  ShieldCheck,
  SlidersHorizontal,
  View,
  Wrench,
} from 'lucide-react';
import {useLocation, useMatch} from 'react-router';
import {type EntityType} from 'gmp/utils/entity-type';
import {isDefined} from 'gmp/utils/identity';
import Link from 'web/components/link/Link';
import useCapabilities from 'web/hooks/useCapabilities';
import useFeatures from 'web/hooks/useFeatures';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';

const Menu = () => {
  const [_] = useTranslation();
  const capabilities = useCapabilities();
  const features = useFeatures();
  const gmp = useGmp();

  const tasksMatch = useMatch('/tasks');
  const taskMatch = useMatch('/task/*');
  const isTasksActive = Boolean(tasksMatch || taskMatch);
  const location = useLocation();

  const reportsMatch = useMatch('/reports');
  const reportMatch = useMatch('/report/*');
  const isReportsActive = Boolean(reportsMatch || reportMatch);

  const scopesMatch = useMatch('/scopes');
  const scopeMatch = useMatch('/scopes/*');
  const scopeReportsMatch = useMatch('/scopes/reports');
  const scopeReportMatch = useMatch('/scopes/:scopeId/reports/*');
  const legacyScopeMatch = useMatch('/scope/*');
  const legacyScopeReportMatch = useMatch('/scope-report/*');
  const isScopeReportsActive = Boolean(
    scopeReportsMatch || scopeReportMatch || legacyScopeReportMatch,
  );
  const isScopesActive = Boolean(
    scopesMatch || legacyScopeMatch || (scopeMatch && !isScopeReportsActive),
  );

  const resultsMatch = useMatch('/results');
  const resultMatch = useMatch('/result/*');
  const isResultsActive = Boolean(resultsMatch || resultMatch);

  const vulnerabilitiesMatch = useMatch('/vulnerabilities');
  const vulnerabilityMatch = useMatch('/vulnerability/*');
  const isVulnerabilitiesActive = Boolean(
    vulnerabilitiesMatch || vulnerabilityMatch,
  );

  const overridesMatch = useMatch('/overrides');
  const overrideMatch = useMatch('/override/*');
  const isOverridesActive = Boolean(overridesMatch || overrideMatch);

  const hostsMatch = useMatch('/hosts');
  const hostDetailsMatch = useMatch('/host/*');
  const isHostsActive = Boolean(hostsMatch || hostDetailsMatch);

  const operatingSystemsMatch = useMatch('/operating-systems');
  const operatingSystemMatch = useMatch('/operating-system/*');
  const isOperatingSystemsActive = Boolean(
    operatingSystemsMatch || operatingSystemMatch,
  );

  const tlsCertificatesMatch = useMatch('/tls-certificates');
  const tlsCertificateMatch = useMatch('/tls-certificate/*');
  const isTlsCertificatesActive = Boolean(
    tlsCertificatesMatch || tlsCertificateMatch,
  );

  const nvtsMatch = useMatch('/nvts');
  const nvtMatch = useMatch('/nvt/*');
  const isNvtsActive = Boolean(nvtsMatch || nvtMatch);

  const cvesMatch = useMatch('/cves');
  const cveMatch = useMatch('/cve/*');
  const isCvesActive = Boolean(cvesMatch || cveMatch);

  const cpesMatch = useMatch('/cpes');
  const cpeMatch = useMatch('/cpe/*');
  const isCpesActive = Boolean(cpesMatch || cpeMatch);

  const certbundsMatch = useMatch('/cert-bund-advisories');
  const certbundMatch = useMatch('/cert-bund-advisory/*');
  const isCertbundsActive = Boolean(certbundsMatch || certbundMatch);

  const dfncertsMatch = useMatch('/dfn-cert-advisories');
  const dfncertMatch = useMatch('/dfn-cert-advisory/*');
  const isDfncertsActive = Boolean(dfncertsMatch || dfncertMatch);

  const targetsMatch = useMatch('/targets');
  const targetMatch = useMatch('/target/*');
  const isTargetsActive = Boolean(targetsMatch || targetMatch);

  const portlistsMatch = useMatch('/port-lists');
  const portlistMatch = useMatch('/port-list/*');
  const isPortlistsActive = Boolean(portlistsMatch || portlistMatch);

  const credentialsMatch = useMatch('/credentials');
  const credentialMatch = useMatch('/credential/*');
  const isCredentialsActive = Boolean(credentialsMatch || credentialMatch);

  const scanConfigsMatch = useMatch('/scan-configs');
  const scanConfigMatch = useMatch('/scan-config/*');
  const isScanConfigsActive = Boolean(scanConfigsMatch || scanConfigMatch);

  const alertsMatch = useMatch('/alerts');
  const alertMatch = useMatch('/alert/*');
  const isAlertsActive = Boolean(alertsMatch || alertMatch);

  const schedulesMatch = useMatch('/schedules');
  const scheduleMatch = useMatch('/schedule/*');
  const isSchedulesActive = Boolean(schedulesMatch || scheduleMatch);

  const reportFormatsMatch = useMatch('/report-formats');
  const reportFormatMatch = useMatch('/report-format/*');
  const isReportFormatsActive = Boolean(
    reportFormatsMatch || reportFormatMatch,
  );

  const scannersMatch = useMatch('/scanners');
  const scannerMatch = useMatch('/scanner/*');
  const isScannersActive = Boolean(scannersMatch || scannerMatch);

  const filtersMatch = useMatch('/filters');
  const filterMatch = useMatch('/filter/*');
  const isFiltersActive = Boolean(filtersMatch || filterMatch);

  const tagsMatch = useMatch('/tags');
  const tagMatch = useMatch('/tag/*');
  const isTagsActive = Boolean(tagsMatch || tagMatch);

  const usersMatch = useMatch('/users');
  const userMatch = useMatch('/user/*');
  const isUserActive = Boolean(usersMatch || userMatch);

  const isPerformanceActive = Boolean(useMatch('/performance'));
  const isTrashcanActive = Boolean(useMatch('/trashcan'));
  const isFeedStatusActive = Boolean(useMatch('/feed-status'));
  const isLdapActive = Boolean(useMatch('/ldap'));
  const isCredentialStoreActive = Boolean(useMatch('/credential-store'));
  const isRadiusActive = Boolean(useMatch('/radius'));
  const mayAccessAny = (keys: EntityType[]) =>
    keys.some(key => isDefined(capabilities) && capabilities.mayAccess(key));

  const mayOpScans = mayAccessAny([
    'task',
    'scope',
    'scopereport',
    'report',
    'result',
    'vulnerability',
    'override',
  ]);
  const mayOpConfiguration = mayAccessAny([
    'target',
    'portlist',
    'credential',
    'scanconfig',
    'alert',
    'schedule',
    'reportformat',
    'scanner',
    'filter',
    'tag',
  ]);
  const mayOpAssets = mayAccessAny(['asset', 'tlscertificate']);

  const menuPoints = [
    [
      mayOpScans && {
        icon: ShieldCheck,
        label: _('Scans'),
        key: 'scans',
        defaultOpened: [
          isTasksActive,
          isScopesActive,
          isScopeReportsActive,
          isReportsActive,
          isResultsActive,
          isVulnerabilitiesActive,
          isOverridesActive,
        ].some(Boolean),
        subNav: [
          capabilities.mayAccess('task') && {
            label: _('Tasks'),
            to: '/tasks',
            isPathMatch: Boolean(tasksMatch),
            active: isTasksActive,
          },
          capabilities.mayAccess('scope') && {
            label: _('Scopes'),
            to: '/scopes',
            isPathMatch: Boolean(scopesMatch),
            active: isScopesActive,
          },
          capabilities.mayAccess('scope') && {
            label: _('Scope Reports'),
            to: '/scopes/reports',
            isPathMatch: Boolean(scopeReportsMatch),
            active: isScopeReportsActive,
          },
          capabilities.mayAccess('report') && {
            label: _('Reports'),
            to: '/reports',
            isPathMatch: Boolean(reportsMatch),
            active: isReportsActive,
          },
          capabilities.mayAccess('result') && {
            label: _('Results'),
            to: '/results',
            isPathMatch: Boolean(resultsMatch),
            active: isResultsActive,
          },
          capabilities.mayAccess('vulnerability') && {
            label: _('Vulnerabilities'),
            to: '/vulnerabilities',
            isPathMatch: Boolean(vulnerabilitiesMatch),
            active: isVulnerabilitiesActive,
          },
          capabilities.mayAccess('override') && {
            label: _('Overrides'),
            to: '/overrides',
            isPathMatch: Boolean(overridesMatch),
            active: isOverridesActive,
          },
        ].filter(Boolean),
      },
      mayOpAssets && {
        icon: Server,
        label: _('Assets'),
        key: 'assets',
        defaultOpened: [
          isHostsActive,
          isOperatingSystemsActive,
          isTlsCertificatesActive,
        ].some(Boolean),
        subNav: [
          capabilities.mayAccess('host') && {
            label: _('Hosts'),
            to: '/hosts',
            isPathMatch: Boolean(hostsMatch),
            active: isHostsActive,
          },
          capabilities.mayAccess('operatingsystem') && {
            label: _('Operating Systems'),
            to: '/operating-systems',
            isPathMatch: Boolean(operatingSystemsMatch),
            active: isOperatingSystemsActive,
          },
          capabilities.mayAccess('tlscertificate') && {
            label: _('TLS Certificates'),
            to: '/tls-certificates',
            isPathMatch: Boolean(tlsCertificatesMatch),
            active: isTlsCertificatesActive,
          },
        ].filter(Boolean),
      },
      capabilities.mayAccess('info') && {
        icon: View,
        label: _('Security Information'),
        key: 'secInfo',
        defaultOpened: [
          isNvtsActive,
          isCvesActive,
          isCpesActive,
          isCertbundsActive,
          isDfncertsActive,
        ].some(Boolean),
        subNav: [
          {
            label: _('NVTs'),
            to: '/nvts',
            isPathMatch: Boolean(nvtsMatch),
            active: isNvtsActive,
          },
          {
            label: _('CVEs'),
            to: '/cves',
            isPathMatch: Boolean(cvesMatch),
            active: isCvesActive,
          },
          {
            label: _('CPEs'),
            to: '/cpes',
            isPathMatch: Boolean(cpesMatch),
            active: isCpesActive,
          },
          {
            label: _('CERT-Bund Advisories'),
            to: '/cert-bund-advisories',
            isPathMatch: Boolean(certbundsMatch),
            active: isCertbundsActive,
          },
          {
            label: _('DFN-CERT Advisories'),
            to: '/dfn-cert-advisories',
            isPathMatch: Boolean(dfncertsMatch),
            active: isDfncertsActive,
          },
        ],
      },
      mayOpConfiguration && {
        icon: Wrench,
        label: _('Configuration'),
        key: 'configuration',
        defaultOpened: [
          isTargetsActive,
          isPortlistsActive,
          isCredentialsActive,
          isScanConfigsActive,
          isAlertsActive,
          isSchedulesActive,
          isReportFormatsActive,
          isScannersActive,
          isFiltersActive,
          isTagsActive,
        ].some(Boolean),
        subNav: [
          capabilities.mayAccess('target') && {
            label: _('Targets'),
            to: '/targets',
            isPathMatch: Boolean(targetsMatch),
            active: isTargetsActive,
          },
          capabilities.mayAccess('portlist') && {
            label: _('Port Lists'),
            to: '/port-lists',
            isPathMatch: Boolean(portlistsMatch),
            active: isPortlistsActive,
          },
          capabilities.mayAccess('credential') && {
            label: _('Credentials'),
            to: '/credentials',
            isPathMatch: Boolean(credentialsMatch),
            active: isCredentialsActive,
          },
          capabilities.mayAccess('scanconfig') && {
            label: _('Scan Configs'),
            to: '/scan-configs',
            isPathMatch: Boolean(scanConfigsMatch),
            active: isScanConfigsActive,
          },
          capabilities.mayAccess('alert') && {
            label: _('Alerts'),
            to: '/alerts',
            isPathMatch: Boolean(alertsMatch),
            active: isAlertsActive,
          },
          capabilities.mayAccess('schedule') && {
            label: _('Schedules'),
            to: '/schedules',
            isPathMatch: Boolean(schedulesMatch),
            active: isSchedulesActive,
          },
          capabilities.mayAccess('reportformat') && {
            label: _('Report Formats'),
            to: '/report-formats',
            isPathMatch: Boolean(reportFormatsMatch),
            active: isReportFormatsActive,
          },
          capabilities.mayAccess('scanner') && {
            label: _('Scanners'),
            to: '/scanners',
            isPathMatch: Boolean(scannersMatch),
            active: isScannersActive,
          },
          capabilities.mayAccess('filter') && {
            label: _('Filters'),
            to: '/filters',
            isPathMatch: Boolean(filtersMatch),
            active: isFiltersActive,
          },
          capabilities.mayAccess('tag') && {
            label: _('Tags'),
            to: '/tags',
            isPathMatch: Boolean(tagsMatch),
            active: isTagsActive,
          },
        ].filter(Boolean),
      },
      {
        label: _('Administration'),
        key: 'administration',
        icon: SlidersHorizontal,
        defaultOpened: [
          isUserActive,
          isPerformanceActive,
          isTrashcanActive,
          isFeedStatusActive,
          isLdapActive,
          isCredentialStoreActive,
          isRadiusActive,
        ].some(Boolean),
        subNav: [
          capabilities.mayAccess('user') && {
            label: _('Users'),
            to: '/users',
            isPathMatch: Boolean(usersMatch),
            active: isUserActive,
          },
          capabilities.mayOp('get_system_reports') && {
            label: _('Performance'),
            to: '/performance',
            isPathMatch: isPerformanceActive,
            active: isPerformanceActive,
          },
          {
            label: _('Trashcan'),
            to: '/trashcan',
            isPathMatch: isTrashcanActive,
            active: isTrashcanActive,
          },
          capabilities.mayOp('get_feeds') && {
            label: _('Feed Status'),
            to: '/feed-status',
            isPathMatch: isFeedStatusActive,
            active: isFeedStatusActive,
          },
          capabilities.mayOp('describe_auth') &&
            capabilities.mayOp('modify_auth') && {
              label: _('LDAP'),
              to: '/ldap',
              isPathMatch: isLdapActive,
              active: isLdapActive,
            },
          capabilities.mayOp('describe_auth') &&
            features.featureEnabled('ENABLE_CREDENTIAL_STORES') &&
            capabilities.mayOp('modify_auth') && {
              label: _('Credential Store'),
              to: '/credential-store',
              isPathMatch: isCredentialStoreActive,
              active: isCredentialStoreActive,
            },
          capabilities.mayOp('describe_auth') &&
            capabilities.mayOp('modify_auth') && {
              label: _('RADIUS'),
              to: '/radius',
              isPathMatch: isRadiusActive,
              active: isRadiusActive,
            },
        ].filter(Boolean),
      },
    ].filter(Boolean),
    [
      gmp.settings.enableAssetManagement && {
        label: _('Asset'),
        to: '/asset-management',
        isExternal: true,
      },
    ].filter(Boolean),
  ];
  return (
    <AppNavigation
      key={location.pathname}
      as={Link}
      // @ts-expect-error
      menuPoints={menuPoints}
    />
  );
};

export default Menu;

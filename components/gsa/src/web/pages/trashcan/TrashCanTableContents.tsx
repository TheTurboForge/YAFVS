/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {type TrashCanGetData} from 'gmp/commands/trashcan';
import type Model from 'gmp/models/model';
import {isDefined} from 'gmp/utils/identity';
import TableBody from 'web/components/table/TableBody';
import useTranslation from 'web/hooks/useTranslation';
import TrashCanTableRow from 'web/pages/trashcan/TrashCanTableRow';

interface TrashCanContentsTableProps {
  trash?: TrashCanGetData;
}

const hasItems = (items: Model[]): boolean => {
  return isDefined(items) && items.length > 0;
};

const TrashCanTableContents = ({trash}: TrashCanContentsTableProps) => {
  const [_] = useTranslation();

  if (!isDefined(trash)) {
    return null;
  }

  const hasAlerts = hasItems(trash.alerts);
  const hasCredentials = hasItems(trash.credentials);
  const hasFilters = hasItems(trash.filters);
  const hasOverrides = hasItems(trash.overrides);
  const hasPortLists = hasItems(trash.portLists);
  const hasReportConfigs = hasItems(trash.reportConfigs);
  const hasReportFormats = hasItems(trash.reportFormats);
  const hasScanners = hasItems(trash.scanners);
  const hasSchedules = hasItems(trash.schedules);
  const hasTags = hasItems(trash.tags);
  const hasTargets = hasItems(trash.targets);
  const hasTasks = hasItems(trash.tasks);
  const hasScanConfigs = hasItems(trash.scanConfigs);

  return (
    <TableBody>
      {hasAlerts && (
        <TrashCanTableRow
          count={trash.alerts.length}
          title={_('Alerts')}
          type="alert"
        />
      )}
      {hasCredentials && (
        <TrashCanTableRow
          count={trash.credentials.length}
          title={_('Credentials')}
          type="credential"
        />
      )}
      {hasFilters && (
        <TrashCanTableRow
          count={trash.filters.length}
          title={_('Filters')}
          type="filter"
        />
      )}
      {hasOverrides && (
        <TrashCanTableRow
          count={trash.overrides.length}
          title={_('Overrides')}
          type="override"
        />
      )}
      {hasPortLists && (
        <TrashCanTableRow
          count={trash.portLists.length}
          title={_('Port Lists')}
          type="port-list"
        />
      )}
      {hasReportConfigs && (
        <TrashCanTableRow
          count={trash.reportConfigs.length}
          title={_('Report Configs')}
          type="report-config"
        />
      )}
      {hasReportFormats && (
        <TrashCanTableRow
          count={trash.reportFormats.length}
          title={_('Report Formats')}
          type="report-format"
        />
      )}
      {hasScanConfigs && (
        <TrashCanTableRow
          count={trash.scanConfigs.length}
          title={_('Scan Configs')}
          type="scan-config"
        />
      )}
      {hasScanners && (
        <TrashCanTableRow
          count={trash.scanners.length}
          title={_('Scanners')}
          type="scanner"
        />
      )}
      {hasSchedules && (
        <TrashCanTableRow
          count={trash.schedules.length}
          title={_('Schedules')}
          type="schedule"
        />
      )}
      {hasTags && (
        <TrashCanTableRow
          count={trash.tags.length}
          title={_('Tags')}
          type="tag"
        />
      )}
      {hasTargets && (
        <TrashCanTableRow
          count={trash.targets.length}
          title={_('Targets')}
          type="target"
        />
      )}
      {hasTasks && (
        <TrashCanTableRow
          count={trash.tasks.length}
          title={_('Tasks')}
          type="task"
        />
      )}
    </TableBody>
  );
};

export default TrashCanTableContents;

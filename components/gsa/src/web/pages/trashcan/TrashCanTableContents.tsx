/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {type TrashCanGetData} from 'gmp/commands/trashcan';
import {type NativeTrashcanSummary} from 'gmp/native-api/trashcan';
import type Model from 'gmp/models/model';
import {isDefined} from 'gmp/utils/identity';
import TableBody from 'web/components/table/TableBody';
import useTranslation from 'web/hooks/useTranslation';
import TrashCanTableRow from 'web/pages/trashcan/TrashCanTableRow';

interface TrashCanContentsTableProps {
  trash?: TrashCanGetData;
  summary?: NativeTrashcanSummary;
}

const itemCount = (items: Model[] | undefined): number => {
  return isDefined(items) ? items.length : 0;
};

const countFor = (
  summary: NativeTrashcanSummary | undefined,
  resourceType: string,
  fallback: number,
): number => {
  const item = summary?.items.find(row => row.resource_type === resourceType);
  return item?.count ?? fallback;
};

const TrashCanTableContents = ({
  trash,
  summary,
}: TrashCanContentsTableProps) => {
  const [_] = useTranslation();

  if (!isDefined(trash)) {
    return null;
  }

  const alertCount = countFor(summary, 'alerts', itemCount(trash.alerts));
  const credentialCount = countFor(
    summary,
    'credentials',
    itemCount(trash.credentials),
  );
  const filterCount = countFor(summary, 'filters', itemCount(trash.filters));
  const overrideCount = countFor(
    summary,
    'overrides',
    itemCount(trash.overrides),
  );
  const portListCount = countFor(
    summary,
    'port_lists',
    itemCount(trash.portLists),
  );
  const reportConfigCount = countFor(
    summary,
    'report_configs',
    itemCount(trash.reportConfigs),
  );
  const reportFormatCount = countFor(
    summary,
    'report_formats',
    itemCount(trash.reportFormats),
  );
  const scannerCount = countFor(summary, 'scanners', itemCount(trash.scanners));
  const scheduleCount = countFor(
    summary,
    'schedules',
    itemCount(trash.schedules),
  );
  const tagCount = countFor(summary, 'tags', itemCount(trash.tags));
  const targetCount = countFor(summary, 'targets', itemCount(trash.targets));
  const taskCount = countFor(summary, 'tasks', itemCount(trash.tasks));
  const scanConfigCount = countFor(
    summary,
    'scan_configs',
    itemCount(trash.scanConfigs),
  );

  return (
    <TableBody>
      {alertCount > 0 && (
        <TrashCanTableRow count={alertCount} title={_('Alerts')} type="alert" />
      )}
      {credentialCount > 0 && (
        <TrashCanTableRow
          count={credentialCount}
          title={_('Credentials')}
          type="credential"
        />
      )}
      {filterCount > 0 && (
        <TrashCanTableRow
          count={filterCount}
          title={_('Filters')}
          type="filter"
        />
      )}
      {overrideCount > 0 && (
        <TrashCanTableRow
          count={overrideCount}
          title={_('Overrides')}
          type="override"
        />
      )}
      {portListCount > 0 && (
        <TrashCanTableRow
          count={portListCount}
          title={_('Port Lists')}
          type="port-list"
        />
      )}
      {reportConfigCount > 0 && (
        <TrashCanTableRow
          count={reportConfigCount}
          title={_('Report Configs')}
          type="report-config"
        />
      )}
      {reportFormatCount > 0 && (
        <TrashCanTableRow
          count={reportFormatCount}
          title={_('Report Formats')}
          type="report-format"
        />
      )}
      {scanConfigCount > 0 && (
        <TrashCanTableRow
          count={scanConfigCount}
          title={_('Scan Configs')}
          type="scan-config"
        />
      )}
      {scannerCount > 0 && (
        <TrashCanTableRow
          count={scannerCount}
          title={_('Scanners')}
          type="scanner"
        />
      )}
      {scheduleCount > 0 && (
        <TrashCanTableRow
          count={scheduleCount}
          title={_('Schedules')}
          type="schedule"
        />
      )}
      {tagCount > 0 && (
        <TrashCanTableRow
          count={tagCount}
          title={_('Tags')}
          type="tag"
        />
      )}
      {targetCount > 0 && (
        <TrashCanTableRow
          count={targetCount}
          title={_('Targets')}
          type="target"
        />
      )}
      {taskCount > 0 && (
        <TrashCanTableRow count={taskCount} title={_('Tasks')} type="task" />
      )}
    </TableBody>
  );
};

export default TrashCanTableContents;

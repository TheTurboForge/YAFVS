/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {type Date} from 'gmp/models/date';
import {GREENBONE_SENSOR_SCANNER_TYPE} from 'gmp/models/scanner';
import {
  type default as Task,
  type TaskTrend as TaskTrendType,
} from 'gmp/models/task';
import {isDefined} from 'gmp/utils/identity';
import SeverityBar from 'web/components/bar/SeverityBar';
import Comment from 'web/components/comment/Comment';
import DateTime from 'web/components/date/DateTime';
import {SensorIcon} from 'web/components/icon';
import IconDivider from 'web/components/layout/IconDivider';
import Layout from 'web/components/layout/Layout';
import DetailsLink from 'web/components/link/DetailsLink';
import Link from 'web/components/link/Link';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import RowDetailsToggle from 'web/entities/RowDetailsToggle';
import useTranslation from 'web/hooks/useTranslation';
import TaskActions, {type TaskActionsProps} from 'web/pages/tasks/TaskActions';
import TaskStatus from 'web/pages/tasks/TaskStatus';
import TaskTrend from 'web/pages/tasks/TaskTrend';

interface TaskReportProps {
  report?: {id?: string; timestamp?: Date};
  links?: boolean;
}

interface TaskReportTotalProps {
  task: Task;
  links?: boolean;
}

export interface TaskRowProps extends TaskActionsProps {
  actionsComponent?: React.ComponentType<TaskActionsProps>;
  onToggleDetailsClick: (entity: Task, id: string) => void;
}

const TaskReport = ({report, links}: TaskReportProps) => {
  if (!isDefined(report)) {
    return null;
  }
  return (
    <span>
      <DetailsLink id={report.id as string} textOnly={!links} type="report">
        <DateTime date={report.timestamp} />
      </DetailsLink>
    </span>
  );
};

const TaskReportTotal = ({task, links = true}: TaskReportTotalProps) => {
  const {report_count: reportCount} = task;
  const [_] = useTranslation();
  if (!isDefined(reportCount?.total) || reportCount.total <= 0) {
    return null;
  }
  return (
    <Layout>
      <Link
        filter={`task_id=${task.id} sort-reverse=date`}
        textOnly={!links || reportCount.total === 0}
        title={_(
          'View list of all reports for Task {{name}},' +
            ' including unfinished ones',
          {name: task.name as string},
        )}
        to={'reports'}
      >
        {reportCount.total}
      </Link>
    </Layout>
  );
};

const TaskRow = ({
  actionsComponent: ActionsComponent = TaskActions,
  entity,
  links = true,
  onToggleDetailsClick,
  ...props
}: TaskRowProps) => {
  const [_] = useTranslation();
  const {
    current_report: currentReport,
    scanner,
    last_report: lastReport,
  } = entity;
  const displayedReport = currentReport ?? lastReport;

  return (
    <TableRow>
      <TableData>
        <Layout align="space-between">
          <div>
            <RowDetailsToggle
              name={entity.id}
              onClick={
                onToggleDetailsClick as (value: Task, name?: string) => void
              }
            >
              {entity.name}
            </RowDetailsToggle>
            {entity.comment && <Comment>({entity.comment})</Comment>}
          </div>
          <IconDivider>
            {isDefined(scanner) &&
              scanner.scannerType === GREENBONE_SENSOR_SCANNER_TYPE && (
                <SensorIcon
                  size="small"
                  title={_('Task is configured to run on remote scanner {{name}}', {
                    name: scanner.name as string,
                  })}
                />
              )}
          </IconDivider>
        </Layout>
      </TableData>
      <TableData>
        <TaskStatus links={links} task={entity} />
      </TableData>
      <TableData>
        <TaskReportTotal links={links} task={entity} />
      </TableData>
      <TableData>
        <TaskReport links={links} report={displayedReport} />
      </TableData>
      <TableData>
        {!isDefined(currentReport) && isDefined(lastReport) && (
          <SeverityBar severity={lastReport.severity} />
        )}
      </TableData>
      <TableData align="center">
        <TaskTrend name={entity.trend as TaskTrendType} />
      </TableData>
      <ActionsComponent {...props} entity={entity} links={links} />
    </TableRow>
  );
};

export default TaskRow;

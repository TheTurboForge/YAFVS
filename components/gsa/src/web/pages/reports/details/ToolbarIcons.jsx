/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {isDefined} from 'gmp/utils/identity';
import {
  AddToAssetsIcon,
  DownloadIcon,
  PerformanceIcon,
  RemoveFromAssetsIcon,
  ResultIcon,
  TaskIcon,
  VulnerabilityIcon,
  TlsCertificateIcon,
} from 'web/components/icon';
import ListIcon from 'web/components/icon/ListIcon';
import ManualIcon from 'web/components/icon/ManualIcon';
import Divider from 'web/components/layout/Divider';
import IconDivider from 'web/components/layout/IconDivider';
import DetailsLink from 'web/components/link/DetailsLink';
import Link from 'web/components/link/Link';
import useTranslation from 'web/hooks/useTranslation';
import AlertActions from 'web/pages/reports/details/AlertActions';
import PropTypes from 'web/utils/PropTypes';
const ToolBarIcons = ({
  filter,
  isLoading,
  report,
  reportId,
  showThresholdMessage,
  task,
  threshold,
  onAddToAssetsClick,
  onRemoveFromAssetsClick,
  onReportDownloadClick,
  showError,
  showErrorMessage,
  showSuccessMessage,
}) => {
  const [_] = useTranslation();

  return (
    <Divider margin="15px">
      <IconDivider>
        <ManualIcon
          anchor="reading-a-report"
          page="reports"
          title={_('Help: Reading Reports')}
        />
        <ListIcon page="reports" title={_('Reports List')} />
      </IconDivider>
      {!isLoading && (
        <React.Fragment>
          <IconDivider>
            <AddToAssetsIcon
              title={_('Add to Assets with QoD >= 70% and Overrides enabled')}
              onClick={onAddToAssetsClick}
            />
            <RemoveFromAssetsIcon
              title={_('Remove from Assets')}
              onClick={onRemoveFromAssetsClick}
            />
          </IconDivider>
          <IconDivider>
            <DetailsLink
              id={isDefined(task) ? task.id : ''}
              textOnly={!isDefined(task)}
              title={_('Corresponding Task')}
              type="task"
            >
              <TaskIcon />
            </DetailsLink>
            <Link
              filter={'report_id=' + reportId}
              title={_('Corresponding Results')}
              to="results"
            >
              <ResultIcon />
            </Link>
            <Link
              filter={'report_id=' + reportId}
              title={_('Corresponding Vulnerabilities')}
              to="vulnerabilities"
            >
              <VulnerabilityIcon />
            </Link>
            <Link
              filter={'report_id=' + reportId}
              title={_('Corresponding TLS Certificates')}
              to="tlscertificates"
            >
              <TlsCertificateIcon />
            </Link>
            {isDefined(task) && (
              <Link
                query={{
                  start: isDefined(report.scan_start)
                    ? report.scan_start
                        .utc()
                        .format('YYYY-MM-DDTHH:mm:ss.SSS[Z]')
                    : undefined,
                  end: isDefined(report.scan_end)
                    ? report.scan_end.utc().format('YYYY-MM-DDTHH:mm:ss.SSS[Z]')
                    : undefined,
                  ...(isDefined(report.slave) && {scanner: report.slave.id}),
                }}
                title={_('Corresponding Performance')}
                to="performance"
              >
                <PerformanceIcon />
              </Link>
            )}
          </IconDivider>
          <IconDivider>
            <DownloadIcon
              title={_('Download filtered Report')}
              onClick={onReportDownloadClick}
            />
            <AlertActions
              filter={filter}
              reportId={reportId}
              showError={showError}
              showErrorMessage={showErrorMessage}
              showSuccessMessage={showSuccessMessage}
              showThresholdMessage={showThresholdMessage}
              threshold={threshold}
            />
          </IconDivider>
        </React.Fragment>
      )}
    </Divider>
  );
};

ToolBarIcons.propTypes = {
  filter: PropTypes.filter,
  isLoading: PropTypes.bool,
  report: PropTypes.shape({
    scan_end: PropTypes.date,
    scan_start: PropTypes.date,
    slave: PropTypes.shape({
      id: PropTypes.id.isRequired,
    }),
  }),
  reportId: PropTypes.id.isRequired,
  showError: PropTypes.func.isRequired,
  showErrorMessage: PropTypes.func.isRequired,
  showSuccessMessage: PropTypes.func.isRequired,
  showThresholdMessage: PropTypes.bool,
  task: PropTypes.model,
  threshold: PropTypes.number,
  onAddToAssetsClick: PropTypes.func.isRequired,
  onRemoveFromAssetsClick: PropTypes.func.isRequired,
  onReportDownloadClick: PropTypes.func.isRequired,
};

export default ToolBarIcons;

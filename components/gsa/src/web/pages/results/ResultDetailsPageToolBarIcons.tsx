/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Result from 'gmp/models/result';
import {isDefined} from 'gmp/utils/identity';
import {
  ReportIcon,
  TaskIcon,
  NewOverrideIcon,
} from 'web/components/icon';
import ExportIcon from 'web/components/icon/ExportIcon';
import ListIcon from 'web/components/icon/ListIcon';
import ManualIcon from 'web/components/icon/ManualIcon';
import Divider from 'web/components/layout/Divider';
import IconDivider from 'web/components/layout/IconDivider';
import DetailsLink from 'web/components/link/DetailsLink';
import useCapabilities from 'web/hooks/useCapabilities';
import useTranslation from 'web/hooks/useTranslation';

interface ResultDetailsPageToolBarIconsProps {
  entity: Result;
  onOverrideCreateClick: (entity: Result) => void;
  onResultDownloadClick: (entity: Result) => void;
}

const ResultDetailsPageToolBarIcons = ({
  entity,
  onOverrideCreateClick,
  onResultDownloadClick,
}: ResultDetailsPageToolBarIconsProps) => {
  const capabilities = useCapabilities();
  const [_] = useTranslation();

  return (
    <Divider margin="10px">
      <IconDivider>
        <ManualIcon
          anchor="displaying-all-existing-results"
          page="reports"
          title={_('Help: Results')}
        />
        <ListIcon page="results" title={_('Results List')} />
        <ExportIcon
          title={_('Export Result as XML')}
          value={entity}
          onClick={onResultDownloadClick}
        />
      </IconDivider>
      <IconDivider>
        {capabilities.mayCreate('override') && (
          <NewOverrideIcon
            title={_('Add new Override')}
            value={entity}
            onClick={onOverrideCreateClick}
          />
        )}
      </IconDivider>
      <IconDivider>
        {capabilities.mayAccess('task') && isDefined(entity.task) && (
          <DetailsLink id={entity.task.id as string} type="task">
            <TaskIcon
              title={_('Corresponding Task ({{name}})', {
                name: entity.task.name as string,
              })}
            />
          </DetailsLink>
        )}
        {capabilities.mayAccess('report') && isDefined(entity.report) && (
          <DetailsLink id={entity.report.id as string} type="report">
            <ReportIcon title={_('Corresponding Report')} />
          </DetailsLink>
        )}
      </IconDivider>
    </Divider>
  );
};

export default ResultDetailsPageToolBarIcons;

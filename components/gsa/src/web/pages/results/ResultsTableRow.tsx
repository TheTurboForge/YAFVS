/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import type Nvt from 'gmp/models/nvt';
import type Result from 'gmp/models/result';
import {isDefined} from 'gmp/utils/identity';
import {shorten} from 'gmp/utils/string';
import SeverityBar from 'web/components/bar/SeverityBar';
import DateTime from 'web/components/date/DateTime';
import {OverrideIcon} from 'web/components/icon';
import SolutionTypeIcon from 'web/components/icon/SolutionTypeIcon';
import IconDivider from 'web/components/layout/IconDivider';
import Layout from 'web/components/layout/Layout';
import DetailsLink from 'web/components/link/DetailsLink';
import Qod from 'web/components/qod/Qod';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import EntitiesActions, {
  type EntitiesActionsProps,
} from 'web/entities/EntitiesActions';
import RowDetailsToggle from 'web/entities/RowDetailsToggle';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import {renderPercentile, renderScore} from 'web/utils/severity';

export interface ResultTableRowProps extends EntitiesActionsProps<Result> {
  actionsComponent?: React.ComponentType<EntitiesActionsProps<Result>>;
  entity: Result;
  links?: boolean;
  onToggleDetailsClick?: () => void;
}

const ResultTableRow = ({
  actionsComponent: ActionsComponent = EntitiesActions,
  'data-testid': dataTestId = 'result-table-row',
  entity,
  links = true,
  onToggleDetailsClick,
  ...props
}: ResultTableRowProps) => {
  const [_] = useTranslation();
  const {host} = entity;
  let shownName = isDefined(entity.name) ? entity.name : entity.information?.id;
  if (!isDefined(shownName)) {
    shownName = entity.id;
  }
  const hasActiveOverrides =
    isDefined(entity.overrides) &&
    entity.overrides.filter(override => override.isActive()).length > 0;
  const epssScore = entity?.information?.epss?.maxEpss?.score;
  const epssPercentile = entity?.information?.epss?.maxEpss?.percentile;
  const gmp = useGmp();
  const enableEPSS = gmp.settings.enableEPSS;
  return (
    <TableRow data-testid={dataTestId}>
      <TableData>
        <Layout align="space-between">
          <RowDetailsToggle name={entity.id} onClick={onToggleDetailsClick}>
            <span>{shownName}</span>
          </RowDetailsToggle>
          <IconDivider>
            {hasActiveOverrides && (
              <OverrideIcon title={_('There are overrides for this result')} />
            )}
          </IconDivider>
        </Layout>
      </TableData>
      <TableData>
        {isDefined((entity?.information as Nvt | undefined)?.solution) && (
          <SolutionTypeIcon
            type={(entity?.information as Nvt | undefined)?.solution?.type}
          />
        )}
      </TableData>
      <TableData>
        <IconDivider>
          {<SeverityBar severity={entity.severity} />}
        </IconDivider>
      </TableData>
      <TableData align="end">
        <IconDivider>
          {isDefined(entity.qod?.value) && <Qod value={entity.qod.value} />}
        </IconDivider>
      </TableData>
      <TableData title={host?.name}>
        <span>
          {isDefined(host?.id) ? (
            <DetailsLink id={host.id} textOnly={!links} type="host">
              {shorten(host.name, 40)}
            </DetailsLink>
          ) : (
            shorten(host?.name, 40)
          )}
        </span>
      </TableData>
      <TableData title={host?.hostname}>
        <IconDivider>
          {isDefined(host?.hostname) && shorten(host.hostname, 40)}
        </IconDivider>
      </TableData>
      <TableData>{entity.port}</TableData>
      {enableEPSS && (
        <>
          <TableData>{renderScore(epssScore)}</TableData>
          <TableData>{renderPercentile(epssPercentile)}</TableData>
        </>
      )}
      <TableData>
        <DateTime date={entity.creationTime} />
      </TableData>
      <ActionsComponent {...props} entity={entity} />
    </TableRow>
  );
};

export default ResultTableRow;

/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import SeverityBar from 'web/components/bar/SeverityBar';
import DateTime from 'web/components/date/DateTime';
import Link from 'web/components/link/Link';
import Qod from 'web/components/qod/Qod';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import EntitiesActions from 'web/entities/EntitiesActions';
import RowDetailsToggle from 'web/entities/RowDetailsToggle';
import PropTypes from 'web/utils/PropTypes';

const Row = ({
  actionsComponent: ActionsComponent = EntitiesActions,
  entity,
  links = true,
  onToggleDetailsClick,
  ...props
}) => {
  const {results = {}, hosts = {}} = entity;
  return (
    <TableRow>
      <TableData>
        <span>
          <RowDetailsToggle name={entity.id} onClick={onToggleDetailsClick}>
            {entity.name}
          </RowDetailsToggle>
        </span>
      </TableData>
      <TableData>
        <DateTime date={results.oldest} />
      </TableData>
      <TableData>
        <DateTime date={results.newest} />
      </TableData>
      <TableData>
        <SeverityBar severity={entity.severity} />
      </TableData>
      <TableData align="center">
        <Qod value={entity.qod} />
      </TableData>
      <TableData>
        <span>
          <Link filter={'nvt=' + entity.id} textOnly={!links} to="results">
            {results.count}
          </Link>
        </span>
      </TableData>
      <TableData>{hosts.count}</TableData>
      <ActionsComponent {...props} entity={entity} />
    </TableRow>
  );
};

Row.propTypes = {
  actionsComponent: PropTypes.component,
  entity: PropTypes.object.isRequired,
  links: PropTypes.bool,
  onToggleDetailsClick: PropTypes.func.isRequired,
};

export default Row;

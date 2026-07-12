/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import Comment from 'web/components/comment/Comment';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import EntityNameTableData from 'web/entities/EntityNameTableData';
import useTranslation from 'web/hooks/useTranslation';
import PropTypes from 'web/utils/PropTypes';
import {renderYesNo} from 'web/utils/Render';
import {formattedUserSettingShortDate} from 'web/utils/user-setting-time-date-formatters';

const Row = ({entity, links = true, onToggleDetailsClick}) => {
  const [_] = useTranslation();

  return (
    <TableRow>
      <EntityNameTableData
        displayName={_('Report Format')}
        entity={entity}
        links={links}
        type="reportformat"
        onToggleDetailsClick={onToggleDetailsClick}
      >
        {entity.summary && <Comment>({entity.summary})</Comment>}
      </EntityNameTableData>
      <TableData>{entity.extension}</TableData>
      <TableData>{entity.content_type}</TableData>
      <TableData flex="column">
        <span>{renderYesNo(entity.trust.value)}</span>
        {entity.trust.time && (
          <span>({formattedUserSettingShortDate(entity.trust.time)})</span>
        )}
      </TableData>
      <TableData>{renderYesNo(entity.isActive())}</TableData>
    </TableRow>
  );
};

Row.propTypes = {
  entity: PropTypes.model.isRequired,
  links: PropTypes.bool,
  onToggleDetailsClick: PropTypes.func.isRequired,
};

export default Row;

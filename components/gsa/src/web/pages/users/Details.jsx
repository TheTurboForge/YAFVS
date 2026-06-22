/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {AUTH_METHOD_LDAP, AUTH_METHOD_RADIUS} from 'gmp/models/user';
import Layout from 'web/components/layout/Layout';
import InfoTable from 'web/components/table/InfoTable';
import TableBody from 'web/components/table/TableBody';
import TableCol from 'web/components/table/TableCol';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import useTranslation from 'web/hooks/useTranslation';
import PropTypes from 'web/utils/PropTypes';

export const convert_auth_method = (auth_method, _) => {
  if (auth_method === AUTH_METHOD_LDAP) {
    return _('LDAP');
  }
  if (auth_method === AUTH_METHOD_RADIUS) {
    return _('RADIUS');
  }
  return _('Local');
};

const UserDetails = ({entity}) => {
  const [_] = useTranslation();
  const {authMethod, comment} = entity;
  return (
    <Layout grow flex="column">
      <InfoTable>
        <colgroup>
          <TableCol width="10%" />
          <TableCol width="90%" />
        </colgroup>
        <TableBody>
          <TableRow>
            <TableData>{_('Comment')}</TableData>
            <TableData>{comment}</TableData>
          </TableRow>

          <TableRow>
            <TableData>{_('Authentication Type')}</TableData>
            <TableData>{convert_auth_method(authMethod, _)}</TableData>
          </TableRow>
        </TableBody>
      </InfoTable>
    </Layout>
  );
};

UserDetails.propTypes = {
  entity: PropTypes.model.isRequired,
};

export default UserDetails;

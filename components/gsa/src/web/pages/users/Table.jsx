/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {_l} from 'gmp/locale/lang';
import createEntitiesFooter from 'web/entities/createEntitiesFooter';
import createEntitiesTable from 'web/entities/createEntitiesTable';
import withRowDetails from 'web/entities/withRowDetails';
import UserDetails from 'web/pages/users/Details';
import Header from 'web/pages/users/Header';
import Row from 'web/pages/users/Row';

export const SORT_FIELDS = [
  {
    name: 'name',
    displayName: _l('Name'),
  },
  {
    name: 'ldap',
    displayName: _l('Authentication Type'),
  },
];

const UsersTable = createEntitiesTable({
  emptyTitle: _l('No Users available'),
  header: Header,
  row: Row,
  rowDetails: withRowDetails('user')(UserDetails),
  footer: createEntitiesFooter({
    download: 'users.xml',
    span: 4,
    delete: true,
  }),
});

export default UsersTable;

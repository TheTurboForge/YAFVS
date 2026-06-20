/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {isDefined} from 'gmp/utils/identity';
import SeverityBar from 'web/components/bar/SeverityBar';
import DateTime from 'web/components/date/DateTime';
import Layout from 'web/components/layout/Layout';
import Link from 'web/components/link/Link';
import Qod from 'web/components/qod/Qod';
import InfoTable from 'web/components/table/InfoTable';
import TableBody from 'web/components/table/TableBody';
import TableCol from 'web/components/table/TableCol';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import useTranslation from 'web/hooks/useTranslation';
import PropTypes from 'web/utils/PropTypes';

const renderNa = (_, value) =>
  isDefined(value) && value !== '' ? value : _('N/A');

const VulnerabilityDetails = ({entity, links = true}) => {
  const [_] = useTranslation();
  const {hosts = {}, results = {}} = entity;

  return (
    <Layout grow flex="column">
      <InfoTable>
        <colgroup>
          <TableCol width="10%" />
          <TableCol width="90%" />
        </colgroup>
        <TableBody>
          <TableRow>
            <TableData>{_('Name')}</TableData>
            <TableData>{renderNa(_, entity.name)}</TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('OID')}</TableData>
            <TableData>{renderNa(_, entity.id)}</TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('Severity')}</TableData>
            <TableData>
              {isDefined(entity.severity) ? (
                <SeverityBar severity={entity.severity} />
              ) : (
                _('N/A')
              )}
            </TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('QoD')}</TableData>
            <TableData>
              {isDefined(entity.qod) ? <Qod value={entity.qod} /> : _('N/A')}
            </TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('Oldest Result')}</TableData>
            <TableData>
              {isDefined(results.oldest) ? (
                <DateTime date={results.oldest} />
              ) : (
                _('N/A')
              )}
            </TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('Newest Result')}</TableData>
            <TableData>
              {isDefined(results.newest) ? (
                <DateTime date={results.newest} />
              ) : (
                _('N/A')
              )}
            </TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('Results')}</TableData>
            <TableData>
              <Link
                filter={'nvt=' + entity.id}
                textOnly={!links}
                to="results"
              >
                {renderNa(_, results.count)}
              </Link>
            </TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('Hosts')}</TableData>
            <TableData>{renderNa(_, hosts.count)}</TableData>
          </TableRow>
        </TableBody>
      </InfoTable>
    </Layout>
  );
};

VulnerabilityDetails.propTypes = {
  entity: PropTypes.object.isRequired,
  links: PropTypes.bool,
};

export default VulnerabilityDetails;

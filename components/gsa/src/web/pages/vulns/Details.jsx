/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {isDefined} from 'gmp/utils/identity';
import SeverityBar from 'web/components/bar/SeverityBar';
import DateTime from 'web/components/date/DateTime';
import CveLink from 'web/components/link/CveLink';
import Layout from 'web/components/layout/Layout';
import Link from 'web/components/link/Link';
import Qod from 'web/components/qod/Qod';
import InfoTable from 'web/components/table/InfoTable';
import TableBody from 'web/components/table/TableBody';
import TableCol from 'web/components/table/TableCol';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import DetailsBlock from 'web/entity/DetailsBlock';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import NvtReferences from 'web/pages/nvts/NvtReferences';
import Pre from 'web/pages/nvts/Preformatted';
import Solution from 'web/pages/nvts/Solution';
import PropTypes from 'web/utils/PropTypes';
import {renderPercentile, renderScore} from 'web/utils/severity';

const renderNa = (_, value) =>
  isDefined(value) && value !== '' ? value : _('N/A');

const DetailTextBlock = ({title, value}) =>
  isDefined(value) && value !== '' ? (
    <DetailsBlock title={title}>
      <Pre>{value}</Pre>
    </DetailsBlock>
  ) : null;

DetailTextBlock.propTypes = {
  title: PropTypes.toString.isRequired,
  value: PropTypes.string,
};

const EpssDetails = ({epss, title}) => {
  const [_] = useTranslation();
  if (!isDefined(epss)) {
    return null;
  }
  return (
    <>
      <h3>{title}</h3>
      <InfoTable>
        <TableBody>
          <TableRow>
            <TableData>{_('EPSS Score')}</TableData>
            <TableData>{renderScore(epss.score)}</TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('EPSS Percentile')}</TableData>
            <TableData>{renderPercentile(epss.percentile)}</TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('CVE')}</TableData>
            <TableData>
              <CveLink id={epss.cve?.id}>{epss.cve?.id}</CveLink>
            </TableData>
          </TableRow>
          <TableRow>
            <TableData>{_('CVE Severity')}</TableData>
            <TableData>
              <SeverityBar
                severity={
                  isDefined(epss.cve?.severity) ? epss.cve?.severity : _('N/A')
                }
              />
            </TableData>
          </TableRow>
        </TableBody>
      </InfoTable>
    </>
  );
};

EpssDetails.propTypes = {
  epss: PropTypes.object,
  title: PropTypes.toString.isRequired,
};

const VulnerabilityDetails = ({entity, links = true}) => {
  const [_] = useTranslation();
  const {hosts = {}, results = {}} = entity;
  const gmp = useGmp();
  const epss = entity.epss;

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
            <TableData>{_('Family')}</TableData>
            <TableData>{renderNa(_, entity.family)}</TableData>
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
              <Link filter={'nvt=' + entity.id} textOnly={!links} to="results">
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
      {gmp.settings.enableEPSS &&
        (isDefined(epss?.maxSeverity) || isDefined(epss?.maxEpss)) && (
          <DetailsBlock title={_('EPSS')}>
            <EpssDetails
              epss={epss?.maxSeverity}
              title={_('EPSS (CVE with highest severity)')}
            />
            <EpssDetails
              epss={epss?.maxEpss}
              title={_('EPSS (highest EPSS score)')}
            />
          </DetailsBlock>
        )}
      <DetailTextBlock title={_('Summary')} value={entity.summary} />
      <DetailTextBlock title={_('Insight')} value={entity.insight} />
      <DetailTextBlock title={_('Detection Method')} value={entity.detection} />
      <DetailTextBlock
        title={_('Affected Software/OS')}
        value={entity.affected}
      />
      <DetailTextBlock title={_('Impact')} value={entity.impact} />
      <Solution
        solutionDescription={entity.solution?.description}
        solutionType={entity.solution?.type}
      />
      <NvtReferences links={links} nvt={entity} />
    </Layout>
  );
};

VulnerabilityDetails.propTypes = {
  entity: PropTypes.object.isRequired,
  links: PropTypes.bool,
};

export default VulnerabilityDetails;

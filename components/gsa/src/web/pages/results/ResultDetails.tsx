/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import styled from 'styled-components';
import {type default as Nvt, TAG_NA} from 'gmp/models/nvt';
import {DEFAULT_OID_VALUE} from 'gmp/models/override';
import type Result from 'gmp/models/result';
import {isDefined} from 'gmp/utils/identity';
import {isEmpty} from 'gmp/utils/string';
import Layout from 'web/components/layout/Layout';
import DetailsLink from 'web/components/link/DetailsLink';
import InfoTable from 'web/components/table/InfoTable';
import TableBody from 'web/components/table/TableBody';
import TableCol from 'web/components/table/TableCol';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import DetailsBlock from 'web/entity/DetailsBlock';
import useTranslation from 'web/hooks/useTranslation';
import NvtReferences from 'web/pages/nvts/NvtReferences';
import P from 'web/pages/nvts/Preformatted';
import Solution from 'web/pages/nvts/Solution';
import {renderNvtName} from 'web/utils/Render';

export interface ResultDetailsProps {
  className?: string;
  entity: Result;
  links?: boolean;
}

/*
 security and log messages from nvts are converted to results
 results should preserve newlines AND whitespaces for formatting
*/
const Pre = styled.pre`
  white-space: pre-wrap;
  word-wrap: break-word;
`;

const GrowDiv = styled.div`
  min-width: 500px;
  max-width: 1080px;
`;

const ResultDetails = ({
  className,
  links = true,
  entity,
}: ResultDetailsProps) => {
  const [_] = useTranslation();
  const result = entity;

  const {information} = result;
  const {id: infoId, tags = {}, solution} = information as Nvt;

  const hasDetection =
    isDefined(result.detection) && isDefined(result.detection.result);

  const detectionDetails = hasDetection
    ? result.detection.result.details
    : undefined;

  return (
    <Layout className={className} flex="column" grow="1">
      {isDefined(tags.summary) && (
        <DetailsBlock title={_('Summary')}>
          <P>{tags.summary}</P>
        </DetailsBlock>
      )}

      <DetailsBlock title={_('Detection Result')}>
        {!isEmpty(result.description) && (result.description?.length || 0) > 1 ? (
          <GrowDiv>
            <Pre>{result.description}</Pre>
          </GrowDiv>
        ) : (
          _('Vulnerability was detected according to the Detection Method.')
        )}
      </DetailsBlock>

      {hasDetection && (
        <DetailsBlock title={_('Product Detection Result')}>
          <InfoTable>
            <TableBody>
              <TableRow>
                <TableData>{_('Product')}</TableData>
                <TableData>
                  <span>
                    <DetailsLink
                      id={detectionDetails?.product as string}
                      textOnly={!links}
                      type="cpe"
                    >
                      {detectionDetails?.product}
                    </DetailsLink>
                  </span>
                </TableData>
              </TableRow>
              <TableRow>
                <TableData>{_('Method')}</TableData>
                <TableData>
                  <span>
                    <DetailsLink
                      id={detectionDetails?.source_oid as string}
                      textOnly={!links}
                      type={
                        (detectionDetails?.source_oid as string).startsWith(
                          'CVE-',
                        )
                          ? 'cve'
                          : 'nvt'
                      }
                    >
                      {detectionDetails?.source_name +
                        ' (OID: ' +
                        detectionDetails?.source_oid +
                        ')'}
                    </DetailsLink>
                  </span>
                </TableData>
              </TableRow>
              <TableRow>
                <TableData>{_('Log')}</TableData>
                <TableData>
                  <span>
                    <DetailsLink
                      id={result.detection.result.id as string}
                      textOnly={!links}
                      type="result"
                    >
                      {_('View details of product detection')}
                    </DetailsLink>
                  </span>
                </TableData>
              </TableRow>
            </TableBody>
          </InfoTable>
        </DetailsBlock>
      )}

      {isDefined(tags.insight) && tags.insight !== TAG_NA && (
        <DetailsBlock title={_('Insight')}>
          <P>{tags.insight}</P>
        </DetailsBlock>
      )}

      <DetailsBlock title={_('Detection Method')}>
        <Layout flex="column">
          <P>{tags.vuldetect}</P>
          <InfoTable>
            <colgroup>
              <TableCol width="10%" />
              <TableCol width="90%" />
            </colgroup>
            <TableBody>
              <TableRow>
                <TableData>{_('Details: ')}</TableData>
                <TableData>
                  {isDefined(infoId) &&
                    infoId.startsWith(DEFAULT_OID_VALUE) && (
                      <span>
                        <DetailsLink id={infoId} textOnly={!links} type="nvt">
                          {renderNvtName(infoId, information?.name)}
                          {' OID: ' + infoId}
                        </DetailsLink>
                      </span>
                    )}
                  {isDefined(infoId) && infoId.startsWith('CVE-') && (
                    <span>
                      <DetailsLink id={infoId} textOnly={!links} type="cve">
                        {renderNvtName(infoId, information?.name)}
                        {' (OID: ' + infoId + ')'}
                      </DetailsLink>
                    </span>
                  )}
                  {!isDefined(infoId) &&
                    _('No details available for this method.')}
                </TableData>
              </TableRow>
              {isDefined(result.scan_nvt_version) && (
                <TableRow>
                  <TableData>{_('Version used: ')}</TableData>
                  <TableData>{result.scan_nvt_version}</TableData>
                </TableRow>
              )}
            </TableBody>
          </InfoTable>
        </Layout>
      </DetailsBlock>

      {isDefined(tags.affected) && tags.affected !== TAG_NA && (
        <DetailsBlock title={_('Affected Software/OS')}>
          <P>{tags.affected}</P>
        </DetailsBlock>
      )}

      {isDefined(tags.impact) && tags.impact !== TAG_NA && (
        <DetailsBlock title={_('Impact')}>
          <P>{tags.impact}</P>
        </DetailsBlock>
      )}

      <Solution
        solutionDescription={solution?.description}
        solutionType={solution?.type}
      />

      {isDefined(information) && (information as Nvt)?.entityType === 'nvt' && (
        <NvtReferences links={links} nvt={information as Nvt} />
      )}
    </Layout>
  );
};

export default ResultDetails;

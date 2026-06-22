/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import styled from 'styled-components';
import TurboVASLogo from 'web/components/img/TurboVASLogo';
import PageTitle from 'web/components/layout/PageTitle';
import useTranslation from 'web/hooks/useTranslation';

const NotFoundLogo = styled(TurboVASLogo)`
  width: 300px;
  color: #111111;
  font-size: 42px;
  margin-bottom: 20px;
`;

const CenteredDiv = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  height: 80vh;
  width: 100%;
`;

const PageNotFound = () => {
  const [_] = useTranslation();

  return (
    <CenteredDiv>
      <PageTitle title={_('Page Not Found')} />
      <h1>{_('Page Not Found.')}</h1>
      <NotFoundLogo />
      <p>
        {_('We are sorry. The page you have requested could not be found.')}
      </p>
    </CenteredDiv>
  );
};

export default PageNotFound;

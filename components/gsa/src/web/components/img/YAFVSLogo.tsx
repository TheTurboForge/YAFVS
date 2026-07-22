/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type {HTMLAttributes} from 'react';
import styled from 'styled-components';

const Wordmark = styled.div`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 120px;
  max-width: 100%;
  height: 48px;
  color: #ffffff;
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 0;
  line-height: 1;
  white-space: nowrap;
`;

interface YAFVSLogoProps extends HTMLAttributes<HTMLDivElement> {
  className?: string;
}

const YAFVSLogo = ({className, ...props}: YAFVSLogoProps) => (
  <Wordmark
    aria-label="YAFVS"
    className={className}
    data-testid="YAFVSLogo"
    {...props}
  >
    YAFVS
  </Wordmark>
);

export default YAFVSLogo;

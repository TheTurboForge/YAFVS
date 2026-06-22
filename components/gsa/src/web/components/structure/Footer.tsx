/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import styled from 'styled-components';
import {VERSION} from 'version';
import Theme from 'web/utils/Theme';

const Footer = styled.footer`
  padding: 2px;
  font-size: 10px;
  text-align: center;
  color: ${Theme.mediumGray};
  margin-top: 10px;
`;

const ProductFooter = () => {
  return (
    <Footer>
      TurboVAS {VERSION} · Independent project
    </Footer>
  );
};

export default ProductFooter;

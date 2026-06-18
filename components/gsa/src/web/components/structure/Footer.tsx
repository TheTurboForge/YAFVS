/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
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

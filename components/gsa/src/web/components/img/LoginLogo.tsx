/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import styled from 'styled-components';
import YAFVSLogo from 'web/components/img/YAFVSLogo';

const StyledLogo = styled(YAFVSLogo)`
  width: 300px;
  height: 72px;
  color: #111111;
  font-size: 42px;
  justify-content: center;
`;

const LoginLogo = () => {
  return <StyledLogo data-testid="login-logo" />;
};

export default LoginLogo;

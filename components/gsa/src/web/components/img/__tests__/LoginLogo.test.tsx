/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {rendererWith} from 'web/testing';
import LoginLogo from 'web/components/img/LoginLogo';

describe('LoginLogo tests', () => {
  test('should render', () => {
    const {render} = rendererWith({
      gmp: {settings: {}},
    });
    const {element} = render(<LoginLogo />);

    expect(element).toHaveTextContent('TurboVAS');
    expect(element).toHaveAttribute('data-testid', 'login-logo');
  });

  test('should render TurboVAS logo when vendorLabel is set', () => {
    const {render} = rendererWith({
      gmp: {settings: {vendorLabel: 'test'}},
    });
    const {element} = render(<LoginLogo />);

    expect(element).toHaveTextContent('TurboVAS');
    expect(element).toHaveAttribute('data-testid', 'login-logo');
  });
});

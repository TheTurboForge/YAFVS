/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {rendererWith, screen} from 'web/testing';
import Footer from 'web/components/structure/Footer';

describe('Footer tests', () => {
  test('should render footer with TurboVAS version and independent project label', () => {
    const {render} = rendererWith({store: true});

    render(<Footer />);

    expect(screen.getByText(/TurboVAS 0\.1\.0-alpha\.0/)).toBeInTheDocument();
    expect(screen.getByText(/Independent project/)).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
});

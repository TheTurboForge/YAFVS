/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {rendererWith, screen} from 'web/testing';
import PageNotFound from 'web/pages/NotFoundPage';

const gmp = {
  settings: {vendorTitle: 'TurboVAS'},
};

describe('PageNotFound tests', () => {
  test('renders the page title', () => {
    const {render} = rendererWith({gmp});
    render(<PageNotFound />);
    expect(document.title).toEqual('TurboVAS - Page Not Found');
  });

  test('renders the main heading', () => {
    const {render} = rendererWith({gmp});
    render(<PageNotFound />);
    expect(screen.getByRole('heading', {level: 1})).toHaveTextContent(
      'Page Not Found.',
    );
  });

  test('renders the TurboVAS logo', () => {
    const {render} = rendererWith({gmp});
    render(<PageNotFound />);
    expect(screen.getByTestId('TurboVASLogo')).toBeInTheDocument();
  });

  test('renders the error message', () => {
    const {render} = rendererWith({gmp});
    render(<PageNotFound />);
    expect(
      screen.getByText(
        'We are sorry. The page you have requested could not be found.',
      ),
    ).toBeInTheDocument();
  });
});

/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {screen, render, waitFor} from 'web/testing';
import getLogo from 'web/components/structure/GetLogo';
import {type ApplianceLogo} from 'web/utils/appliance-data';

describe('getLogo', () => {
  const testCases = [
    'gsm-150_label.svg',
    'gsm-400_label.svg',
    'gsm-400r2_label.svg',
    'gsm-450_label.svg',
    'gsm-450r2_label.svg',
    'gsm-600_label.svg',
    'gsm-600r2_label.svg',
    'gsm-650_label.svg',
    'gsm-650r2_label.svg',
    'gsm-5400_label.svg',
    'gsm-6500_label.svg',
    'gsm-ceno_label.svg',
    'gsm-deca_label.svg',
    'gsm-exa_label.svg',
    'gsm-peta_label.svg',
    'gsm-tera_label.svg',
    'gsm-unknown_label.svg',
    'defaultVendorLabel',
  ];

  test.each(testCases)('returns YAFVS branding for %s', async logo => {
    render(getLogo(logo as ApplianceLogo));
    await waitFor(() => {
      expect(screen.getByTestId('YAFVSLogo')).toBeInTheDocument();
      expect(screen.getByText('YAFVS')).toBeInTheDocument();
    });
  });
});

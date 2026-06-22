/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import TurboVASLogo from 'web/components/img/TurboVASLogo';

export type ApplianceLogo = keyof typeof APPLIANCE_DATA;

const APPLIANCE_DATA = {
  defaultVendorLabel: {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-150_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-400_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-400r2_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-450_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-450r2_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-600_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-600r2_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-650_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-650r2_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-5400_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-6500_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-ceno_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-deca_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-exa_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-peta_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-tera_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'enterprise-container.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
  'gsm-unknown_label.svg': {
    title: 'TurboVAS',
    component: TurboVASLogo,
  },
};

export const applianceTitle = Object.fromEntries(
  Object.entries(APPLIANCE_DATA).map(([vendorLabel, {title}]) => [
    vendorLabel,
    title,
  ]),
);

export const applianceComponent = Object.fromEntries(
  Object.entries(APPLIANCE_DATA).map(([vendorLabel, {component}]) => [
    vendorLabel,
    component,
  ]),
);

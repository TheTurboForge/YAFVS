/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import YAFVSLogo from 'web/components/img/YAFVSLogo';

export type ApplianceLogo = keyof typeof APPLIANCE_DATA;

const APPLIANCE_DATA = {
  defaultVendorLabel: {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-150_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-400_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-400r2_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-450_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-450r2_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-600_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-600r2_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-650_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-650r2_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-5400_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-6500_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-ceno_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-deca_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-exa_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-peta_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-tera_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'enterprise-container.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
  },
  'gsm-unknown_label.svg': {
    title: 'YAFVS',
    component: YAFVSLogo,
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

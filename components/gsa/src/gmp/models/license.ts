/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import _ from 'gmp/locale';
import {type Date} from 'gmp/models/date';
import {type ModelElement} from 'gmp/models/model';
import {parseDate} from 'gmp/parser';
import {isDefined} from 'gmp/utils/identity';

type ApplianceModel = keyof typeof LICENSE_MODEL;
type ApplianceModelType = 'virtual' | 'hardware';
type LicenseStatus = 'active' | 'corrupt' | 'expired' | 'no_license';

interface LicenseElement extends ModelElement {
  content: {
    appliance?: {
      model?: ApplianceModel;
      model_type?: ApplianceModelType;
    };
    meta: {
      begins?: string;
      comment?: string;
      created?: string;
      customer_name?: string;
      expires?: string;
      id?: string;
      type?: string;
      version?: string;
    };
  };
  status: LicenseStatus;
}

interface LicenseProperties {
  applianceModel?: ApplianceModel;
  applianceModelType?: ApplianceModelType;
  begins?: Date;
  comment?: string;
  created?: Date;
  customerName?: string;
  expires?: Date;
  id?: string;
  status?: LicenseStatus;
  type?: string;
  version?: string;
}

const LICENSE_MODEL = {
  trial: 'Legacy appliance TRIAL',
  '25v': 'Legacy appliance 25V',
  25: 'Legacy appliance 25',
  35: 'Legacy appliance 35',
  maven: 'Legacy appliance MAVEN',
  one: 'Legacy appliance ONE',
  100: 'Legacy appliance 100',
  150: 'Legacy appliance 150',
  ceno: 'Legacy appliance CENO',
  deca: 'Legacy appliance DECA',
  400: 'Legacy appliance 400',
  '400r2': 'Legacy appliance 400',
  450: 'Legacy appliance 450',
  '450r2': 'Legacy appliance 450',
  tera: 'Legacy appliance TERA',
  500: 'Legacy appliance 500',
  510: 'Legacy appliance 510',
  550: 'Legacy appliance 550',
  600: 'Legacy appliance 600',
  '600r2': 'Legacy appliance 600',
  peta: 'Legacy appliance PETA',
  650: 'Legacy appliance 650',
  '650r2': 'Legacy appliance 650',
  exa: 'Legacy appliance EXA',
  5300: 'Legacy appliance 5300',
  6400: 'Legacy appliance 6400',
  5400: 'Legacy appliance 5400',
  6500: 'Legacy appliance 6500',
  expo: 'Legacy appliance EXPO',
  '150c-siesta': 'Legacy appliance 150C-SiESTA',
} as const;

export const getLicenseApplianceModelName = (value: ApplianceModel) => {
  const name = LICENSE_MODEL[value];
  return isDefined(name) ? name : value;
};

export const getLicenseApplianceModelType = (value?: ApplianceModelType) => {
  if (!isDefined(value)) {
    return value;
  }
  if (value === 'virtual') {
    return 'Virtual Appliance';
  }
  if (value === 'hardware') {
    return 'Hardware Appliance';
  }
  return _('Unknown');
};

export const getTranslatableLicenseStatus = (value: LicenseStatus) => {
  switch (value) {
    case 'active':
      return _('License is active');
    case 'corrupt':
      return _('License is corrupted');
    case 'expired':
      return _('License has expired');
    case 'no_license':
      return _('No license available');
    default:
      return _('N/A');
  }
};

class License {
  readonly applianceModel?: ApplianceModel;
  readonly applianceModelType?: ApplianceModelType;
  readonly begins?: Date;
  readonly comment?: string;
  readonly created?: Date;
  readonly customerName?: string;
  readonly expires?: Date;
  readonly id?: string;
  readonly status?: LicenseStatus;
  readonly type?: string;
  readonly version?: string;

  constructor({
    applianceModel,
    applianceModelType,
    begins,
    comment,
    created,
    customerName,
    expires,
    id,
    status,
    type,
    version,
  }: LicenseProperties) {
    this.status = status;
    this.id = id;
    this.customerName = customerName;
    this.version = version;
    this.created = created;
    this.begins = begins;
    this.expires = expires;
    this.comment = comment;
    this.type = type;

    this.applianceModel = applianceModel;
    this.applianceModelType = applianceModelType;
  }

  static fromElement(element: LicenseElement): License {
    const {content, status} = element;
    return new License({
      status: status,
      id: content?.meta?.id,
      customerName: content?.meta?.customer_name,
      created: parseDate(content?.meta?.created),
      version: content?.meta?.version,
      begins: parseDate(content?.meta?.begins),
      expires: parseDate(content?.meta?.expires),
      comment: content?.meta?.comment,
      type: content?.meta?.type,
      applianceModel: content?.appliance?.model,
      applianceModelType: content?.appliance?.model_type,
    });
  }
}

export default License;

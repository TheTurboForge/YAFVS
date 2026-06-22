/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import Model, {type ModelElement, type ModelProperties} from 'gmp/models/model';
import {isDefined} from 'gmp/utils/identity';

export interface UserElement extends ModelElement {
  sources?: {
    source: string;
  };
}

export interface UserProperties extends ModelProperties {
  authMethod?: string;
}

export const AUTH_METHOD_PASSWORD = 'password';
export const AUTH_METHOD_NEW_PASSWORD = 'newpassword';
export const AUTH_METHOD_LDAP = 'ldap';
export const AUTH_METHOD_RADIUS = 'radius';

class User extends Model {
  static readonly entityType = 'user';

  readonly authMethod?: string;

  constructor({
    authMethod = AUTH_METHOD_PASSWORD,
    ...properties
  }: UserProperties = {}) {
    super(properties);

    this.authMethod = authMethod;
  }

  static fromElement(element: UserElement = {}): User {
    return new User(this.parseElement(element));
  }

  static parseElement(element: UserElement): UserProperties {
    const ret = super.parseElement(element) as UserProperties;

    if (isDefined(element.sources)) {
      const {source} = element.sources;
      if (source === 'ldap_connect') {
        ret.authMethod = AUTH_METHOD_LDAP;
      } else if (source === 'radius_connect') {
        ret.authMethod = AUTH_METHOD_RADIUS;
      }
      // @ts-expect-error
      delete ret.sources;
    } else {
      ret.authMethod = AUTH_METHOD_PASSWORD;
    }

    return ret;
  }
}

export default User;

/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import Model, {type ModelProperties} from 'gmp/models/model';

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
}

export default User;

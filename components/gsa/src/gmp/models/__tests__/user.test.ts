/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {testModel} from 'gmp/models/testing';
import User, {
  AUTH_METHOD_LDAP,
  AUTH_METHOD_RADIUS,
  AUTH_METHOD_PASSWORD,
} from 'gmp/models/user';

testModel(User, 'user');

describe('User model tests', () => {
  test('should retain native auth methods', () => {
    const user1 = new User({id: '123', authMethod: AUTH_METHOD_LDAP});
    const user2 = new User({id: '122', authMethod: AUTH_METHOD_RADIUS});
    const user3 = new User();

    expect(user1.authMethod).toEqual(AUTH_METHOD_LDAP);
    expect(user2.authMethod).toEqual(AUTH_METHOD_RADIUS);
    expect(user3.authMethod).toEqual(AUTH_METHOD_PASSWORD);
  });
});

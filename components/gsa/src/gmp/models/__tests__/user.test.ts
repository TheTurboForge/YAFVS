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
  test('should parse sources to auth_method', () => {
    const elem1 = {
      _id: '123',
      sources: {
        source: 'ldap_connect',
      },
    };
    const elem2 = {
      _id: '122',
      sources: {
        source: 'radius_connect',
      },
    };
    const user1 = User.fromElement(elem1);
    const user2 = User.fromElement(elem2);
    const user3 = User.fromElement();

    expect(user1.authMethod).toEqual(AUTH_METHOD_LDAP);
    expect(user2.authMethod).toEqual(AUTH_METHOD_RADIUS);
    // @ts-expect-error
    expect(user1.sources).toBeUndefined();
    expect(user3.authMethod).toEqual(AUTH_METHOD_PASSWORD);
  });
});

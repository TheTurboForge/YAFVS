/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {RELEASE_VERSION, VERSION} from 'version';

describe('Version tests', () => {
  test('release version should only contain major.minor', () => {
    expect(RELEASE_VERSION.split('.').length).toEqual(2);
  });

  test('YAFVS version should use the WIP alpha series', () => {
    expect(VERSION).toEqual('0.1.0-alpha.0');
    expect(RELEASE_VERSION).toEqual('0.1');
  });
});

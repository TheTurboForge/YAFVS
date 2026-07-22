/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, expect, test} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {nativeTagResourceSelectionFromFilter} from 'gmp/native-api/tag-resource-selection';

describe('native tag resource selection', () => {
  test('maps the live user collection filter to a typed literal selector', () => {
    const filter = Filter.fromString('search=alice first=1 rows=10 sort=name');

    expect(nativeTagResourceSelectionFromFilter('user', filter, 2)).toEqual({
      resourceType: 'user',
      search: 'alice',
      expectedCount: 2,
    });
  });

  test('rejects unsupported user criteria instead of broadening selection', () => {
    const filter = Filter.fromString('name~alice first=1 rows=10 sort=name');

    expect(() =>
      nativeTagResourceSelectionFromFilter('user', filter, 2),
    ).toThrow('Filtered user tagging supports only one literal search');
  });
});

/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {
  reportIdentifier,
  simplifiedReportIdentifier,
  reportSelector,
} from 'web/store/entities/report/selectors';
import {createState} from 'web/store/entities/utils/testing';

describe('reportIdentifier tests', () => {
  test('should create identifier without filter', () => {
    const id = 'foo';
    expect(reportIdentifier(id)).toEqual('foo');
  });

  test('should create identifier with filter', () => {
    const id = 'foo';
    const filter = Filter.fromString('foo=bar rows=10');
    expect(reportIdentifier(id, filter)).toEqual('foo-foo=bar rows=10');
  });
});

describe('simplifiedReportIdentifier tests', () => {
  test('should create identifier without filter', () => {
    const id = 'foo';
    expect(simplifiedReportIdentifier(id)).toEqual('foo');
  });

  test('should create identifier with filter', () => {
    const id = 'foo';
    const filter = Filter.fromString('foo=bar rows=10');
    expect(simplifiedReportIdentifier(id, filter)).toEqual('foo-foo=bar');
  });
});

describe('report selector tests', () => {
  test('should return true for isLoading', () => {
    const state = createState('report', {
      isLoading: {
        foo: true,
      },
    });
    const selector = reportSelector(state);

    expect(selector.isLoadingEntity('foo')).toEqual(true);
  });

  test('should return true for isLoading with filter', () => {
    const filter = Filter.fromString('foo=bar rows=10');
    const state = createState('report', {
      isLoading: {
        [reportIdentifier('foo', filter)]: true,
      },
    });
    const selector = reportSelector(state);

    expect(selector.isLoadingEntity('foo', filter)).toEqual(true);
  });

  test('should return false for isLoading', () => {
    const state = createState('report', {
      isLoading: {
        foo: false,
      },
    });
    const selector = reportSelector(state);

    expect(selector.isLoadingEntity('foo')).toEqual(false);
  });

  test('should return false for isLoading with filter', () => {
    const filter = Filter.fromString('foo=bar rows=10');
    const state = createState('report', {
      isLoading: {
        [reportIdentifier('foo', filter)]: false,
      },
    });
    const selector = reportSelector(state);

    expect(selector.isLoadingEntity('foo', filter)).toEqual(false);
  });

  test('should return undefined for isLoading', () => {
    let state = createState('report', {});
    let selector = reportSelector(state);
    expect(selector.isLoadingEntity('foo')).toBeUndefined();

    state = createState('report', {
      isLoading: {},
    });
    selector = reportSelector(state);
    expect(selector.isLoadingEntity('foo')).toBeUndefined();

    state = createState('report', {
      isLoading: {
        foo: undefined,
      },
    });
    selector = reportSelector(state);
    expect(selector.isLoadingEntity('foo')).toBeUndefined();
  });

  test('should return undefined for isLoading with filter', () => {
    const filter = Filter.fromString('foo=bar rows=10');
    let state = createState('report', {
      isLoading: {
        foo: true,
      },
    });
    let selector = reportSelector(state);
    expect(selector.isLoadingEntity('foo', filter)).toBeUndefined();

    state = createState('report', {
      isLoading: {
        [reportIdentifier('foo', filter)]: undefined,
      },
    });
    selector = reportSelector(state);
    expect(selector.isLoadingEntity('foo', filter)).toBeUndefined();
  });

  test('should return error', () => {
    const state = createState('report', {
      errors: {
        foo: 'An error',
      },
    });
    const selector = reportSelector(state);
    expect(selector.getEntityError('foo')).toEqual('An error');
  });

  test('should return error with filter', () => {
    const filter = Filter.fromString('foo=bar rows=10');
    const state = createState('report', {
      errors: {
        [reportIdentifier('foo', filter)]: 'An error',
      },
    });
    const selector = reportSelector(state);
    expect(selector.getEntityError('foo', filter)).toEqual('An error');
  });

  test('should return undefined error', () => {
    const filter = Filter.fromString('foo=bar rows=10');
    const state = createState('report', {
      errors: {
        [simplifiedReportIdentifier('foo', filter)]: 'An error',
      },
    });
    const selector = reportSelector(state);
    expect(selector.getEntityError('foo')).toBeUndefined();
  });

  test('should return undefined error with filter', () => {
    const filter = Filter.fromString('foo=bar rows=10');
    const state = createState('report', {
      errors: {
        foo: 'An error',
      },
    });
    const selector = reportSelector(state);
    expect(selector.getEntityError('foo', filter)).toBeUndefined();
  });

  test('should return report', () => {
    const model = {id: 'foo'};
    const state = createState('report', {
      byId: {
        foo: model,
      },
    });
    const selector = reportSelector(state);
    expect(selector.getEntity('foo')).toBe(model);
  });

  test('should return report with filter', () => {
    const model = {id: 'foo'};
    const filter = Filter.fromString('foo=bar rows=10');
    const state = createState('report', {
      byId: {
        [simplifiedReportIdentifier('foo', filter)]: model,
      },
    });
    const selector = reportSelector(state);
    expect(selector.getEntity('foo', filter)).toBe(model);
  });

  test('should return report with simplified filter', () => {
    const model = {id: 'foo'};
    const filter = Filter.fromString('foo=bar rows=10');
    const filter2 = Filter.fromString('foo=bar first=10');
    const state = createState('report', {
      byId: {
        [simplifiedReportIdentifier('foo', filter)]: model,
      },
    });
    const selector = reportSelector(state);
    expect(selector.getEntity('foo', filter2)).toBe(model);
  });
});

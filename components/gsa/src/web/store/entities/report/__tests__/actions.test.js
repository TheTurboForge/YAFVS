/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {isFunction} from 'gmp/utils/identity';
import {
  loadReport,
  loadReportIfNeeded,
  loadReportWithThreshold,
  reportActions,
} from 'web/store/entities/report/actions';
import {reportIdentifier} from 'web/store/entities/report/selectors';
import {types} from 'web/store/entities/utils/actions';
import {createState, testEntityActions} from 'web/store/entities/utils/testing';

testEntityActions('report', reportActions);

describe('loadReport function tests', () => {
  test('should load report successfully', () => {
    const id = 'a1';
    const rootState = createState('report', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const get = testing.fn().mockResolvedValue({
      data: {foo: 'bar'},
    });

    const gmp = {
      report: {
        get,
      },
    };

    expect(loadReport).toBeDefined();
    expect(isFunction(loadReport)).toBe(true);

    expect.assertions(7);

    return loadReport(gmp)(id)(dispatch, getState).then(() => {
      expect(getState).toBeCalled();
      expect(get).toBeCalledWith({id}, {details: true, filter: undefined});
      expect(dispatch).toHaveBeenCalledTimes(2);
      expect(dispatch).toHaveBeenNthCalledWith(1, {
        type: types.ENTITY_LOADING_REQUEST,
        entityType: 'report',
        id,
      });
      expect(dispatch).toHaveBeenNthCalledWith(2, {
        type: types.ENTITY_LOADING_SUCCESS,
        entityType: 'report',
        data: {foo: 'bar'},
        id,
      });
    });
  });

  test('should load report with results filter successfully', () => {
    const id = 'a1';
    const rootState = createState('report', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const get = testing.fn().mockResolvedValue({
      data: {foo: 'bar'},
    });

    const gmp = {
      report: {
        get,
      },
    };

    const filter = Filter.fromString('foo=bar');

    expect(loadReport).toBeDefined();
    expect(isFunction(loadReport)).toBe(true);

    expect.assertions(7);

    return loadReport(gmp)(id, {filter})(dispatch, getState).then(() => {
      expect(getState).toBeCalled();
      expect(get).toBeCalledWith({id}, {details: true, filter});
      expect(dispatch).toHaveBeenCalledTimes(2);
      expect(dispatch).toHaveBeenNthCalledWith(1, {
        type: types.ENTITY_LOADING_REQUEST,
        entityType: 'report',
        filter,
        id,
      });
      expect(dispatch).toHaveBeenNthCalledWith(2, {
        type: types.ENTITY_LOADING_SUCCESS,
        entityType: 'report',
        filter,
        data: {foo: 'bar'},
        id,
      });
    });
  });

  test('should not load report if isLoading is true', () => {
    const id = 'a1';
    const rootState = createState('report', {
      isLoading: {
        [id]: true,
      },
    });

    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const get = testing.fn().mockResolvedValue([{id: 'foo'}]);

    const gmp = {
      report: {
        get,
      },
    };

    expect.assertions(3);

    return loadReport(gmp)(id)(dispatch, getState).then(() => {
      expect(getState).toBeCalled();
      expect(dispatch).not.toBeCalled();
      expect(get).not.toBeCalled();
    });
  });

  test('should fail loading report with an error', () => {
    const id = 'a1';
    const rootState = createState('report', {
      [id]: {
        isLoading: false,
      },
    });

    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const get = testing.fn().mockRejectedValue('An Error');

    const gmp = {
      report: {
        get,
      },
    };

    expect.assertions(5);

    return loadReport(gmp)(id)(dispatch, getState).catch(() => {
      expect(getState).toBeCalled();
      expect(get).toBeCalledWith({id}, {details: true, filter: undefined});
      expect(dispatch).toHaveBeenCalledTimes(2);
      expect(dispatch).toHaveBeenNthCalledWith(1, {
        type: types.ENTITY_LOADING_REQUEST,
        entityType: 'report',
        id,
      });
      expect(dispatch).toHaveBeenNthCalledWith(2, {
        type: types.ENTITY_LOADING_ERROR,
        entityType: 'report',
        error: 'An Error',
        id,
      });
    });
  });
});

describe('report loadReportIfNeeded function tests', () => {
  test('should load report successfully if needed', () => {
    const id = 'a1';
    const rootState = createState('report', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const get = testing.fn().mockResolvedValue({data: {foo: 'bar'}});

    const gmp = {
      report: {
        get,
      },
    };

    expect.assertions(7);

    expect(loadReportIfNeeded).toBeDefined();
    expect(isFunction(loadReportIfNeeded)).toBe(true);

    return loadReportIfNeeded(gmp)(id)(dispatch, getState).then(() => {
      expect(getState).toBeCalled();
      expect(get).toBeCalledWith({id}, {details: false, filter: undefined});
      expect(dispatch).toHaveBeenCalledTimes(2);
      expect(dispatch).toHaveBeenNthCalledWith(1, {
        type: types.ENTITY_LOADING_REQUEST,
        entityType: 'report',
        id,
      });
      expect(dispatch).toHaveBeenNthCalledWith(2, {
        type: types.ENTITY_LOADING_SUCCESS,
        entityType: 'report',
        data: {foo: 'bar'},
        id,
      });
    });
  });

  test('should not load report if report is already in store', () => {
    const id = 'a1';
    const rootState = createState('report', {
      isLoading: {
        [id]: false,
      },
      byId: {
        [id]: 'a1',
      },
    });

    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const get = testing.fn().mockResolvedValue([{id: 'foo'}]);

    const gmp = {
      report: {
        get,
      },
    };

    expect.assertions(3);

    return loadReportIfNeeded(gmp)(id)(dispatch, getState).then(() => {
      expect(getState).toBeCalled();
      expect(dispatch).not.toBeCalled();
      expect(get).not.toBeCalled();
    });
  });

  test('should load report with results filter successfully if needed', () => {
    const id = 'a1';
    const rootState = createState('report', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const get = testing.fn().mockResolvedValue({data: {foo: 'bar'}});

    const gmp = {
      report: {
        get,
      },
    };

    const filter = Filter.fromString('foo=bar');

    expect.assertions(7);

    expect(loadReportIfNeeded).toBeDefined();
    expect(isFunction(loadReportIfNeeded)).toBe(true);

    return loadReportIfNeeded(gmp)(id, {filter})(dispatch, getState).then(
      () => {
        expect(getState).toBeCalled();
        expect(get).toBeCalledWith({id}, {details: false, filter});
        expect(dispatch).toHaveBeenCalledTimes(2);
        expect(dispatch).toHaveBeenNthCalledWith(1, {
          type: types.ENTITY_LOADING_REQUEST,
          entityType: 'report',
          filter,
          id,
        });
        expect(dispatch).toHaveBeenNthCalledWith(2, {
          type: types.ENTITY_LOADING_SUCCESS,
          entityType: 'report',
          filter,
          data: {foo: 'bar'},
          id,
        });
      },
    );
  });

  test('should not load report if isLoading is true', () => {
    const id = 'a1';
    const rootState = createState('report', {
      isLoading: {
        [id]: true,
      },
    });

    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const get = testing.fn().mockResolvedValue([{id: 'foo'}]);

    const gmp = {
      report: {
        get,
      },
    };

    expect.assertions(3);

    return loadReportIfNeeded(gmp)(id)(dispatch, getState).then(() => {
      expect(getState).toBeCalled();
      expect(dispatch).not.toBeCalled();
      expect(get).not.toBeCalled();
    });
  });

  test('should fail loading report with an error', () => {
    const id = 'a1';
    const rootState = createState('report', {
      [id]: {
        isLoading: false,
      },
    });

    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const get = testing.fn().mockRejectedValue('An Error');

    const gmp = {
      report: {
        get,
      },
    };

    expect.assertions(5);

    return loadReportIfNeeded(gmp)(id)(dispatch, getState).catch(() => {
      expect(getState).toBeCalled();
      expect(get).toBeCalledWith({id}, {details: false, filter: undefined});
      expect(dispatch).toHaveBeenCalledTimes(2);
      expect(dispatch.mock.calls[0]).toEqual([
        {
          type: types.ENTITY_LOADING_REQUEST,
          entityType: 'report',
          id,
        },
      ]);
      expect(dispatch.mock.calls[1]).toEqual([
        {
          type: types.ENTITY_LOADING_ERROR,
          entityType: 'report',
          error: 'An Error',
          id,
        },
      ]);
    });
  });
});

describe('loadReportWithThreshold tests', () => {
  test('should only load "simple" report', () => {
    const id = 'a1';
    const rootState = createState('report', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const report = {
      report: {
        results: {
          counts: {
            filtered: 10000,
          },
        },
      },
    };

    const get = testing.fn().mockResolvedValue({
      data: report,
    });

    const gmp = {
      report: {
        get,
      },
      settings: {
        reportResultsThreshold: 1000,
      },
    };

    expect(loadReportWithThreshold).toBeDefined();
    expect(isFunction(loadReportWithThreshold)).toBe(true);

    expect.assertions(7);

    return loadReportWithThreshold(gmp)(id)(dispatch, getState).then(() => {
      expect(getState).toBeCalled();
      expect(get).toBeCalledWith({id}, {details: false, filter: undefined});
      expect(dispatch).toHaveBeenCalledTimes(2);
      expect(dispatch).toHaveBeenNthCalledWith(1, {
        type: types.ENTITY_LOADING_REQUEST,
        entityType: 'report',
        id,
      });
      expect(dispatch).toHaveBeenNthCalledWith(2, {
        type: types.ENTITY_LOADING_SUCCESS,
        entityType: 'report',
        data: report,
        id,
      });
    });
  });

  test('should load "full" report', () => {
    const id = 'a1';
    const rootState = createState('report', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const report = {
      report: {
        results: {
          counts: {
            filtered: 10000,
          },
        },
      },
    };

    const get = testing.fn().mockResolvedValue({
      data: report,
    });

    const gmp = {
      report: {
        get,
      },
      settings: {
        reportResultsThreshold: 100001,
      },
    };

    expect(loadReportWithThreshold).toBeDefined();
    expect(isFunction(loadReportWithThreshold)).toBe(true);

    expect.assertions(11);

    return loadReportWithThreshold(gmp)(id)(dispatch, getState).then(() => {
      expect(getState).toBeCalled();
      expect(get).toHaveBeenCalledTimes(2);
      expect(get).toHaveBeenNthCalledWith(
        1,
        {id},
        {details: false, filter: undefined},
      );
      expect(get).toHaveBeenNthCalledWith(
        2,
        {id},
        {details: true, filter: undefined},
      );
      expect(dispatch).toHaveBeenCalledTimes(4);
      expect(dispatch).toHaveBeenNthCalledWith(1, {
        type: types.ENTITY_LOADING_REQUEST,
        entityType: 'report',
        id,
      });
      expect(dispatch).toHaveBeenNthCalledWith(2, {
        type: types.ENTITY_LOADING_SUCCESS,
        entityType: 'report',
        data: report,
        id,
      });
      expect(dispatch).toHaveBeenNthCalledWith(3, {
        type: types.ENTITY_LOADING_REQUEST,
        entityType: 'report',
        id,
      });
      expect(dispatch).toHaveBeenNthCalledWith(4, {
        type: types.ENTITY_LOADING_SUCCESS,
        entityType: 'report',
        data: report,
        id,
      });
    });
  });

  test('should only load "simple" report with filter', () => {
    const id = 'a1';
    const filter = Filter.fromString('foo=bar rows=10');
    const rootState = createState('report', {
      isLoading: {
        [reportIdentifier(id, filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const report = {
      report: {
        results: {
          counts: {
            filtered: 10000,
          },
        },
      },
    };

    const get = testing.fn().mockResolvedValue({
      data: report,
    });

    const gmp = {
      report: {
        get,
      },
      settings: {
        reportResultsThreshold: 1000,
      },
    };

    expect(loadReportWithThreshold).toBeDefined();
    expect(isFunction(loadReportWithThreshold)).toBe(true);

    expect.assertions(7);

    return loadReportWithThreshold(gmp)(id, {filter})(dispatch, getState).then(
      () => {
        expect(getState).toBeCalled();
        expect(get).toBeCalledWith({id}, {details: false, filter});
        expect(dispatch).toHaveBeenCalledTimes(2);
        expect(dispatch).toHaveBeenNthCalledWith(1, {
          type: types.ENTITY_LOADING_REQUEST,
          entityType: 'report',
          filter,
          id,
        });
        expect(dispatch).toHaveBeenNthCalledWith(2, {
          type: types.ENTITY_LOADING_SUCCESS,
          entityType: 'report',
          filter,
          data: report,
          id,
        });
      },
    );
  });

  test('should load "full" report with filter', () => {
    const id = 'a1';
    const filter = Filter.fromString('foo=bar rows=10');
    const rootState = createState('report', {
      isLoading: {
        [reportIdentifier(id, filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const report = {
      report: {
        results: {
          counts: {
            filtered: 10000,
          },
        },
      },
    };

    const get = testing.fn().mockResolvedValue({
      data: report,
    });

    const gmp = {
      report: {
        get,
      },
      settings: {
        reportResultsThreshold: 100001,
      },
    };

    expect(loadReportWithThreshold).toBeDefined();
    expect(isFunction(loadReportWithThreshold)).toBe(true);

    expect.assertions(11);

    return loadReportWithThreshold(gmp)(id, {filter})(dispatch, getState).then(
      () => {
        expect(getState).toBeCalled();
        expect(get).toHaveBeenCalledTimes(2);
        expect(get).toHaveBeenNthCalledWith(1, {id}, {details: false, filter});
        expect(get).toHaveBeenNthCalledWith(2, {id}, {details: true, filter});
        expect(dispatch).toHaveBeenCalledTimes(4);
        expect(dispatch).toHaveBeenNthCalledWith(1, {
          type: types.ENTITY_LOADING_REQUEST,
          entityType: 'report',
          filter,
          id,
        });
        expect(dispatch).toHaveBeenNthCalledWith(2, {
          type: types.ENTITY_LOADING_SUCCESS,
          entityType: 'report',
          filter,
          data: report,
          id,
        });
        expect(dispatch).toHaveBeenNthCalledWith(3, {
          type: types.ENTITY_LOADING_REQUEST,
          entityType: 'report',
          filter,
          id,
        });
        expect(dispatch).toHaveBeenNthCalledWith(4, {
          type: types.ENTITY_LOADING_SUCCESS,
          entityType: 'report',
          filter,
          data: report,
          id,
        });
      },
    );
  });

  test('should not load report if already loading', () => {
    const id = 'a1';
    const rootState = createState('report', {
      isLoading: {
        [id]: true,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const report = {
      report: {
        results: {
          counts: {
            filtered: 10000,
          },
        },
      },
    };

    const get = testing.fn().mockResolvedValue({
      data: report,
    });

    const gmp = {
      report: {
        get,
      },
      settings: {
        reportResultsThreshold: 1000,
      },
    };

    expect(loadReportWithThreshold).toBeDefined();
    expect(isFunction(loadReportWithThreshold)).toBe(true);

    expect.assertions(5);

    return loadReportWithThreshold(gmp)(id)(dispatch, getState).then(() => {
      expect(getState).toBeCalled();
      expect(get).not.toHaveBeenCalled();
      expect(dispatch).not.toHaveBeenCalled();
    });
  });

  test('should not load report if already loading with filter', () => {
    const id = 'a1';
    const filter = Filter.fromString('foo=bar rows=10');
    const rootState = createState('report', {
      isLoading: {
        [reportIdentifier(id, filter)]: true,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);

    const dispatch = testing.fn();

    const report = {
      report: {
        results: {
          counts: {
            filtered: 10000,
          },
        },
      },
    };

    const get = testing.fn().mockResolvedValue({
      data: report,
    });

    const gmp = {
      report: {
        get,
      },
      settings: {
        reportResultsThreshold: 1000,
      },
    };

    expect(loadReportWithThreshold).toBeDefined();
    expect(isFunction(loadReportWithThreshold)).toBe(true);

    expect.assertions(5);

    return loadReportWithThreshold(gmp)(id, {filter})(dispatch, getState).then(
      () => {
        expect(getState).toBeCalled();
        expect(get).not.toHaveBeenCalled();
        expect(dispatch).not.toHaveBeenCalled();
      },
    );
  });
});

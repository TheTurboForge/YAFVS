/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {isDefined} from 'gmp/utils/identity';
import {reportSelector} from 'web/store/entities/report/selectors';
import {types} from 'web/store/entities/utils/actions';

export const reportActions = {
  request: (id, filter) => ({
    type: types.ENTITY_LOADING_REQUEST,
    entityType: 'report',
    filter,
    id,
  }),
  success: (id, data, filter) => ({
    type: types.ENTITY_LOADING_SUCCESS,
    entityType: 'report',
    data,
    filter,
    id,
  }),
  error: (id, error, filter) => ({
    type: types.ENTITY_LOADING_ERROR,
    entityType: 'report',
    error,
    filter,
    id,
  }),
};

export const loadReport =
  gmp =>
  (id, {filter, details = true, force = false} = {}) =>
  (dispatch, getState) => {
    const rootState = getState();
    const state = reportSelector(rootState);

    if (!force && state.isLoadingEntity(id, filter)) {
      // we are already loading data
      return Promise.resolve();
    }

    dispatch(reportActions.request(id, filter));

    return gmp.report
      .get({id}, {filter, details})
      .then(
        response => response.data,
        error => {
          dispatch(reportActions.error(id, error, filter));
          return Promise.reject(error);
        },
      )
      .then(data => {
        dispatch(reportActions.success(id, data, filter));
        return data;
      });
  };

export const loadReportWithThreshold =
  gmp =>
  (id, {filter} = {}) =>
  (dispatch, getState) => {
    const rootState = getState();
    const state = reportSelector(rootState);

    if (state.isLoadingEntity(id, filter)) {
      // we are already loading data
      return Promise.resolve();
    }

    dispatch(reportActions.request(id, filter));

    const {reportResultsThreshold: threshold} = gmp.settings;
    return gmp.report
      .get({id}, {filter, details: false})
      .then(
        response => response.data,
        error => {
          dispatch(reportActions.error(id, error, filter));
          return Promise.reject(error);
        },
      )
      .then(report => {
        const fullReport =
          isDefined(report) &&
          isDefined(report.report) &&
          isDefined(report.report.results) &&
          report.report.results.counts.filtered < threshold;

        dispatch(reportActions.success(id, report, filter));

        if (fullReport) {
          return loadReport(gmp)(id, {filter, details: true, force: true})(
            dispatch,
            getState,
          );
        }
      });
  };

export const loadReportIfNeeded =
  gmp =>
  (id, {filter, details = false} = {}) =>
  (dispatch, getState) => {
    // loads the small report (without details) if these information are not
    // yet in the store. resolve() otherwise
    const rootState = getState();
    const state = reportSelector(rootState);

    if (isDefined(state.getEntity(id, filter))) {
      // we are already loading data or have it in the store
      return Promise.resolve();
    }
    return loadReport(gmp)(id, {filter, details})(dispatch, getState);
  };

/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {reportReducer} from 'web/store/entities/report/reducers';
import {reportsReducer} from 'web/store/entities/reports/reducers';
import {
  createEntitiesLoadingActions,
  createLoadAllEntities,
  types,
} from 'web/store/entities/utils/actions';
import {initialState} from 'web/store/entities/utils/reducers';
import {createEntitiesSelector} from 'web/store/entities/utils/selectors';
import {
  fetchNativeReports,
  nativeReportQueryFromFilter,
} from 'gmp/native-api/reports';

const reportsSelector = createEntitiesSelector('report');
const entitiesActions = createEntitiesLoadingActions('report');
const loadAllEntities = createLoadAllEntities({
  selector: reportsSelector,
  actions: entitiesActions,
  entityType: 'report',
});
const loadEntities = gmp => filter => (dispatch, getState) => {
  const rootState = getState();
  const state = reportsSelector(rootState);

  if (state.isLoadingEntities(filter)) {
    return Promise.resolve();
  }

  dispatch(entitiesActions.request(filter));

  return fetchNativeReports(gmp, nativeReportQueryFromFilter(filter)).then(
    response =>
      dispatch(
        entitiesActions.success(
          response.reports,
          filter,
          filter,
          response.counts,
        ),
      ),
    error => dispatch(entitiesActions.error(error, filter)),
  );
};

const reducer = (state = initialState, action) => {
  if (action.entityType !== 'report') {
    return state;
  }

  switch (action.type) {
    case types.ENTITIES_LOADING_REQUEST:
    case types.ENTITIES_LOADING_SUCCESS:
    case types.ENTITIES_LOADING_ERROR:
      return reportsReducer(state, action);
    case types.ENTITY_LOADING_REQUEST:
    case types.ENTITY_LOADING_SUCCESS:
    case types.ENTITY_LOADING_ERROR:
      return reportReducer(state, action);
    default:
      return state;
  }
};

export {
  loadAllEntities,
  loadEntities,
  reducer,
  reportsSelector as selector,
  entitiesActions,
};

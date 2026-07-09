/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {createAll} from 'web/store/entities/utils/main';
import {
  fetchNativeSchedule,
  fetchNativeSchedules,
  nativeSchedulesQueryFromFilter,
} from 'gmp/native-api/schedules';

const {
  loadAllEntities,
  entitiesLoadingActions,
  entityLoadingActions,
  reducer,
  selector,
} = createAll('schedule');

const nativeLoadEntities = gmp => filter => (dispatch, getState) => {
  const rootState = getState();
  const state = selector(rootState);

  if (state.isLoadingEntities(filter)) {
    return Promise.resolve();
  }

  dispatch(entitiesLoadingActions.request(filter));

  return fetchNativeSchedules(gmp, nativeSchedulesQueryFromFilter(filter)).then(
    response =>
      dispatch(
        entitiesLoadingActions.success(
          response.schedules,
          filter,
          filter,
          response.counts,
        ),
      ),
    error => dispatch(entitiesLoadingActions.error(error, filter)),
  );
};

const nativeLoadEntity = gmp => id => (dispatch, getState) => {
  const rootState = getState();
  const state = selector(rootState);

  if (state.isLoadingEntity(id)) {
    return Promise.resolve();
  }

  dispatch(entityLoadingActions.request(id));

  return fetchNativeSchedule(gmp, id).then(
    schedule => dispatch(entityLoadingActions.success(id, schedule)),
    error => dispatch(entityLoadingActions.error(id, error)),
  );
};

export {
  loadAllEntities,
  entitiesLoadingActions,
  entityLoadingActions,
  nativeLoadEntities as loadEntities,
  nativeLoadEntity as loadEntity,
  reducer,
  selector,
};

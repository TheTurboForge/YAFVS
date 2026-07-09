/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 * SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {
  fetchNativeNvt,
  fetchNativeNvts,
  nativeNvtsQueryFromFilter,
} from 'gmp/native-api/nvts';
import {createAll} from 'web/store/entities/utils/main';

const {
  loadAllEntities,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('nvt');

const nativeLoadEntities = gmp => filter => (dispatch, getState) => {
  const rootState = getState();
  const state = selector(rootState);

  if (state.isLoadingEntities(filter)) {
    return Promise.resolve();
  }

  dispatch(entitiesLoadingActions.request(filter));

  return fetchNativeNvts(gmp, nativeNvtsQueryFromFilter(filter)).then(
    response =>
      dispatch(
        entitiesLoadingActions.success(
          response.nvts,
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

  return fetchNativeNvt(gmp, id).then(
    response => dispatch(entityLoadingActions.success(id, response.nvt)),
    error => dispatch(entityLoadingActions.error(id, error)),
  );
};

export {
  loadAllEntities,
  nativeLoadEntities as loadEntities,
  nativeLoadEntity as loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
};

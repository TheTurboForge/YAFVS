/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {createAll} from 'web/store/entities/utils/main';
import {
  fetchNativeHost,
  fetchNativeHosts,
  nativeHostsQueryFromFilter,
} from 'gmp/native-api/hosts';

const {
  loadAllEntities,
  loadEntities,
  loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('host');

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const nativeLoadEntities = gmp => filter => (dispatch, getState) => {
  if (!canUseNativeApi(gmp)) {
    return loadEntities(gmp)(filter)(dispatch, getState);
  }

  const rootState = getState();
  const state = selector(rootState);

  if (state.isLoadingEntities(filter)) {
    return Promise.resolve();
  }

  dispatch(entitiesLoadingActions.request(filter));

  return fetchNativeHosts(gmp, nativeHostsQueryFromFilter(filter)).then(
    response =>
      dispatch(
        entitiesLoadingActions.success(
          response.hosts,
          filter,
          filter,
          response.counts,
        ),
      ),
    error => dispatch(entitiesLoadingActions.error(error, filter)),
  );
};

const nativeLoadEntity = gmp => id => (dispatch, getState) => {
  if (!canUseNativeApi(gmp)) {
    return loadEntity(gmp)(id)(dispatch, getState);
  }

  const rootState = getState();
  const state = selector(rootState);

  if (state.isLoadingEntity(id)) {
    return Promise.resolve();
  }

  dispatch(entityLoadingActions.request(id));

  return fetchNativeHost(gmp, id).then(
    response => dispatch(entityLoadingActions.success(id, response.host)),
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

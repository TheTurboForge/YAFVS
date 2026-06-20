/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {createAll} from 'web/store/entities/utils/main';
import {
  fetchNativeOperatingSystem,
  fetchNativeOperatingSystems,
  nativeOperatingSystemsQueryFromFilter,
} from 'gmp/native-api/operating-systems';

const {
  loadAllEntities,
  loadEntities,
  loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('operatingsystem');

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const mergeNativeInformation = (inherited, native) =>
  Object.assign(Object.create(Object.getPrototypeOf(inherited)), inherited, {
    name: native.name,
    creationTime: native.creationTime,
    modificationTime: native.modificationTime,
    averageSeverity: native.averageSeverity,
    highestSeverity: native.highestSeverity,
    latestSeverity: native.latestSeverity,
    title: native.title,
    hosts: native.hosts,
    allHosts: native.allHosts,
  });

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

  return fetchNativeOperatingSystems(
    gmp,
    nativeOperatingSystemsQueryFromFilter(filter),
  ).then(
    response =>
      dispatch(
        entitiesLoadingActions.success(
          response.operatingSystems,
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

  return Promise.all([
    gmp.operatingsystem.get({id}),
    fetchNativeOperatingSystem(gmp, id),
  ]).then(
    ([inheritedResponse, nativeResponse]) =>
      dispatch(
        entityLoadingActions.success(
          id,
          mergeNativeInformation(
            inheritedResponse.data,
            nativeResponse.operatingSystem,
          ),
        ),
      ),
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

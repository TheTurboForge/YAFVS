/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {createAll} from 'web/store/entities/utils/main';
import {
  fetchNativeScanConfig,
  fetchNativeScanConfigFamilies,
  fetchNativeScanConfigs,
  nativeScanConfigsQueryFromFilter,
} from 'gmp/native-api/scan-configs';

const {
  loadAllEntities,
  loadEntities,
  loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('scanconfig');

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const mergeNativeInformation = (inherited, native, nativeFamilies) =>
  Object.assign(Object.create(Object.getPrototypeOf(inherited)), inherited, {
    name: native.name,
    comment: native.comment,
    creationTime: native.creationTime,
    modificationTime: native.modificationTime,
    owner: native.owner,
    family_list: nativeFamilies.family_list,
    families: nativeFamilies.families,
    nvts: native.nvts,
    predefined: native.predefined,
    deprecated: native.deprecated,
    writable: native.writable,
    inUse: native.inUse,
    orphan: native.orphan,
    trash: native.trash,
    tasks: native.tasks,
    userTags: native.userTags,
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

  return fetchNativeScanConfigs(
    gmp,
    nativeScanConfigsQueryFromFilter(filter),
  ).then(
    response =>
      dispatch(
        entitiesLoadingActions.success(
          response.scanConfigs,
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

  return gmp.scanconfig
    .get({id})
    .then(inheritedResponse =>
      Promise.all([
        fetchNativeScanConfig(gmp, id),
        fetchNativeScanConfigFamilies(gmp, id),
      ]).then(([nativeResponse, nativeFamiliesResponse]) =>
        dispatch(
          entityLoadingActions.success(
            id,
            mergeNativeInformation(
              inheritedResponse.data,
              nativeResponse.scanConfig,
              nativeFamiliesResponse.scanConfig,
            ),
          ),
        ),
      ),
    )
    .catch(error => dispatch(entityLoadingActions.error(id, error)));
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

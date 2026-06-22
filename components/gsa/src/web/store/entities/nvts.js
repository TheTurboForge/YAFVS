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
  loadEntities,
  loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('nvt');

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const mergeNativeInformation = (inherited, native) =>
  Object.assign(Object.create(Object.getPrototypeOf(inherited)), inherited, {
    name: native.name,
    comment: native.comment,
    creationTime: native.creationTime,
    modificationTime: native.modificationTime,
    family: native.family,
    qod: native.qod,
    severity: native.severity,
    severityDate: native.severityDate,
    severityOrigin: native.severityOrigin,
    solution: native.solution,
    tags: Object.assign({}, inherited.tags, native.tags),
    certs: native.certs,
    cves: native.cves,
    epss: native.epss,
    xrefs: native.xrefs,
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
  if (!canUseNativeApi(gmp)) {
    return loadEntity(gmp)(id)(dispatch, getState);
  }

  const rootState = getState();
  const state = selector(rootState);

  if (state.isLoadingEntity(id)) {
    return Promise.resolve();
  }

  dispatch(entityLoadingActions.request(id));

  return gmp.nvt
    .get({id})
    .then(inheritedResponse =>
      fetchNativeNvt(gmp, id).then(nativeResponse =>
        dispatch(
          entityLoadingActions.success(
            id,
            mergeNativeInformation(inheritedResponse.data, nativeResponse.nvt),
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

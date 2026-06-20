/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 * SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {
  fetchNativeDfnCertAdvisory,
  fetchNativeDfnCertAdvisories,
  nativeDfnCertAdvisoriesQueryFromFilter,
} from 'gmp/native-api/dfn-cert-advisories';
import {createAll} from 'web/store/entities/utils/main';

const {
  loadAllEntities,
  loadEntities,
  loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('dfncert');

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const mergeNativeInformation = (inherited, native) =>
  Object.assign(Object.create(Object.getPrototypeOf(inherited)), inherited, {
    name: native.name,
    comment: native.comment,
    creationTime: native.creationTime,
    modificationTime: native.modificationTime,
    cve_refs: native.cve_refs,
    cves: native.cves,
    severity: native.severity,
    summary: native.summary,
    title: native.title,
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

  return fetchNativeDfnCertAdvisories(
    gmp,
    nativeDfnCertAdvisoriesQueryFromFilter(filter),
  ).then(
    response =>
      dispatch(
        entitiesLoadingActions.success(
          response.dfncerts,
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
    gmp.dfncert.get({id}),
    fetchNativeDfnCertAdvisory(gmp, id),
  ]).then(
    ([inheritedResponse, nativeResponse]) =>
      dispatch(
        entityLoadingActions.success(
          id,
          mergeNativeInformation(
            inheritedResponse.data,
            nativeResponse.dfncert,
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

/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {createAll} from 'web/store/entities/utils/main';
import {
  fetchNativeTlsCertificates,
  nativeTlsCertificatesQueryFromFilter,
} from 'gmp/native-api/tls-certificates';

const {
  loadAllEntities,
  loadEntities,
  loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('tlscertificate');

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

  return fetchNativeTlsCertificates(
    gmp,
    nativeTlsCertificatesQueryFromFilter(filter),
  ).then(
    response =>
      dispatch(
        entitiesLoadingActions.success(
          response.tlsCertificates,
          filter,
          filter,
          response.counts,
        ),
      ),
    error => dispatch(entitiesLoadingActions.error(error, filter)),
  );
};

export {
  loadAllEntities,
  nativeLoadEntities as loadEntities,
  loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
};

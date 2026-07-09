/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {createAll} from 'web/store/entities/utils/main';
import {
  fetchNativeTlsCertificate,
  fetchNativeTlsCertificates,
  nativeTlsCertificatesQueryFromFilter,
} from 'gmp/native-api/tls-certificates';

const {
  loadAllEntities,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('tlscertificate');

const nativeLoadEntities = gmp => filter => (dispatch, getState) => {
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

const nativeLoadEntity = gmp => id => (dispatch, getState) => {
  const rootState = getState();
  const state = selector(rootState);

  if (state.isLoadingEntity(id)) {
    return Promise.resolve();
  }

  dispatch(entityLoadingActions.request(id));

  return fetchNativeTlsCertificate(gmp, id).then(
    response =>
      dispatch(entityLoadingActions.success(id, response.tlsCertificate)),
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

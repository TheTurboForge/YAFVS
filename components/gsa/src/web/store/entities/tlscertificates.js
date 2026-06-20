/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
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
  loadEntities,
  loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('tlscertificate');

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const mergeNativeInformation = (inherited, native) =>
  Object.assign(Object.create(Object.getPrototypeOf(inherited)), inherited, {
    name: native.name,
    comment: native.comment,
    creationTime: native.creationTime,
    modificationTime: native.modificationTime,
    subjectDn: native.subjectDn,
    issuerDn: native.issuerDn,
    serial: native.serial,
    md5Fingerprint: native.md5Fingerprint,
    sha256Fingerprint: native.sha256Fingerprint,
    activationTime: native.activationTime,
    expirationTime: native.expirationTime,
    lastSeen: native.lastSeen,
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
    gmp.tlscertificate.get({id}),
    fetchNativeTlsCertificate(gmp, id),
  ]).then(
    ([inheritedResponse, nativeResponse]) =>
      dispatch(
        entityLoadingActions.success(
          id,
          mergeNativeInformation(
            inheritedResponse.data,
            nativeResponse.tlsCertificate,
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

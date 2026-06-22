/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {createAll} from 'web/store/entities/utils/main';
import {
  fetchNativeScanner,
  fetchNativeScanners,
  nativeScannersQueryFromFilter,
} from 'gmp/native-api/scanners';
import {CVE_SCANNER_TYPE} from 'gmp/models/scanner';

const {
  loadAllEntities,
  loadEntities,
  loadEntity,
  reducer,
  selector,
  entitiesLoadingActions,
  entityLoadingActions,
} = createAll('scanner');

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const mergeNativeCredentialReference = (
  inheritedCredential,
  nativeCredential,
) => {
  if (nativeCredential === undefined) {
    return inheritedCredential;
  }

  if (inheritedCredential === undefined) {
    return nativeCredential;
  }

  return Object.assign(
    Object.create(Object.getPrototypeOf(inheritedCredential)),
    inheritedCredential,
    {
      id: nativeCredential.id,
      name: nativeCredential.name,
    },
  );
};

const mergeNativeInformation = (inherited, native) =>
  Object.assign(Object.create(Object.getPrototypeOf(inherited)), inherited, {
    name: native.name,
    comment: native.comment,
    creationTime: native.creationTime,
    modificationTime: native.modificationTime,
    host: native.host,
    port: native.port,
    scannerType: native.scannerType,
    credential: mergeNativeCredentialReference(
      inherited.credential,
      native.credential,
    ),
  });

const canUseNativeOnlyDetail = scanner =>
  scanner.hasUnixSocket() || scanner.scannerType === CVE_SCANNER_TYPE;

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

  return fetchNativeScanners(gmp, nativeScannersQueryFromFilter(filter)).then(
    response =>
      dispatch(
        entitiesLoadingActions.success(
          response.scanners,
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

  return fetchNativeScanner(gmp, id)
    .then(nativeResponse => {
      if (canUseNativeOnlyDetail(nativeResponse.scanner)) {
        return dispatch(
          entityLoadingActions.success(id, nativeResponse.scanner),
        );
      }

      return gmp.scanner.get({id}).then(inheritedResponse =>
        dispatch(
          entityLoadingActions.success(
            id,
            mergeNativeInformation(
              inheritedResponse.data,
              nativeResponse.scanner,
            ),
          ),
        ),
      );
    })
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

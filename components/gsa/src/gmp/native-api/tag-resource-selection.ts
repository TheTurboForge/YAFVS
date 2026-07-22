/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Filter from 'gmp/models/filter';
import {nativeCredentialsQueryFromFilter} from 'gmp/native-api/credentials';
import {nativePortListsQueryFromFilter} from 'gmp/native-api/port-lists';
import {nativeScannersQueryFromFilter} from 'gmp/native-api/scanners';
import type {NativeTagResourceSelectionInput} from 'gmp/native-api/tags';
import {nativeTargetQueryFromFilter} from 'gmp/native-api/targets';
import {nativeUserManagementQueryFromFilter} from 'gmp/native-api/users';
import type {EntityType} from 'gmp/utils/entity-type';

const supportedCollectionControlTerms = new Set([
  'first',
  'rows',
  'sort',
  'sort-reverse',
]);

const literalSearchTerms = (filter: Filter) => {
  const criteriaTerms = filter
    .all()
    .getAllTerms()
    .filter(term => !supportedCollectionControlTerms.has(term.keyword ?? ''));
  const searchTerms = criteriaTerms.filter(term => term.keyword === 'search');
  const unkeyedTerms = criteriaTerms.filter(
    term => term.keyword === undefined && term.relation === undefined,
  );
  const onlyLiteralSearch = criteriaTerms.every(
    term =>
      (term.keyword === undefined && term.relation === undefined) ||
      (term.keyword === 'search' &&
        term.relation === '=' &&
        term.value !== undefined),
  );
  return {criteriaTerms, searchTerms, unkeyedTerms, onlyLiteralSearch};
};

const requireOneLiteralSearch = (filter: Filter, resourceName: string) => {
  const {searchTerms, unkeyedTerms, onlyLiteralSearch} =
    literalSearchTerms(filter);
  if (
    !onlyLiteralSearch ||
    searchTerms.length > 1 ||
    unkeyedTerms.length > 1 ||
    (searchTerms.length > 0 && unkeyedTerms.length > 0)
  ) {
    throw new Error(
      `Filtered ${resourceName} tagging supports only one literal search`,
    );
  }
};

const portListResourceSelection = (
  filter: Filter,
  expectedCount: number,
): NativeTagResourceSelectionInput => {
  const selectionFilter = filter.all();
  const criteriaTerms = selectionFilter
    .getAllTerms()
    .filter(term => !supportedCollectionControlTerms.has(term.keyword ?? ''));
  const searchTerms = criteriaTerms.filter(term => term.keyword === 'search');
  const predefinedTerms = criteriaTerms.filter(
    term => term.keyword === 'predefined',
  );
  const unkeyedTerms = criteriaTerms.filter(
    term => term.keyword === undefined && term.relation === undefined,
  );
  const onlySupportedTerms = criteriaTerms.every(
    term =>
      (term.keyword === undefined && term.relation === undefined) ||
      ((term.keyword === 'search' || term.keyword === 'predefined') &&
        term.relation === '=' &&
        term.value !== undefined),
  );
  if (
    !onlySupportedTerms ||
    searchTerms.length > 1 ||
    predefinedTerms.length > 1 ||
    (searchTerms.length > 0 && unkeyedTerms.length > 0)
  ) {
    throw new Error(
      'Filtered port-list tagging supports only literal search and predefined filters',
    );
  }
  const query = nativePortListsQueryFromFilter(selectionFilter);
  if (
    query.predefined !== undefined &&
    query.predefined !== '0' &&
    query.predefined !== '1'
  ) {
    throw new Error('Invalid port-list predefined filter');
  }
  return {
    resourceType: 'port_list',
    ...(query.filter === '' ? {} : {search: query.filter}),
    ...(query.predefined === undefined
      ? {}
      : {predefined: query.predefined === '1'}),
    expectedCount,
  };
};

const credentialResourceSelection = (
  filter: Filter,
  expectedCount: number,
): NativeTagResourceSelectionInput => {
  const selectionFilter = filter.all();
  const criteriaTerms = selectionFilter
    .getAllTerms()
    .filter(term => !supportedCollectionControlTerms.has(term.keyword ?? ''));
  const searchTerms = criteriaTerms.filter(term => term.keyword === 'search');
  const credentialTypeTerms = criteriaTerms.filter(
    term => term.keyword === 'type' || term.keyword === 'credential_type',
  );
  const unkeyedTerms = criteriaTerms.filter(
    term => term.keyword === undefined && term.relation === undefined,
  );
  const onlySupportedTerms = criteriaTerms.every(
    term =>
      (term.keyword === undefined && term.relation === undefined) ||
      ((term.keyword === 'search' ||
        term.keyword === 'type' ||
        term.keyword === 'credential_type') &&
        term.relation === '=' &&
        term.value !== undefined),
  );
  if (
    !onlySupportedTerms ||
    searchTerms.length > 1 ||
    credentialTypeTerms.length > 1 ||
    (searchTerms.length > 0 && unkeyedTerms.length > 0) ||
    (credentialTypeTerms.length > 0 && unkeyedTerms.length > 0)
  ) {
    throw new Error(
      'Filtered credential tagging supports only literal search and exact credential type filters',
    );
  }
  const query = nativeCredentialsQueryFromFilter(selectionFilter);
  return {
    resourceType: 'credential',
    ...(query.filter === '' ? {} : {search: query.filter}),
    ...(query.credentialType === undefined
      ? {}
      : {credentialType: query.credentialType}),
    expectedCount,
  };
};

export const nativeTagResourceSelectionFromFilter = (
  resourceType: EntityType,
  filter: Filter,
  expectedCount: number,
): NativeTagResourceSelectionInput | undefined => {
  switch (resourceType) {
    case 'portlist':
      return portListResourceSelection(filter, expectedCount);
    case 'credential': {
      return credentialResourceSelection(filter, expectedCount);
    }
    case 'scanner': {
      requireOneLiteralSearch(filter, 'scanner');
      const query = nativeScannersQueryFromFilter(filter.all());
      return {
        resourceType: 'scanner',
        ...(query.filter === '' ? {} : {search: query.filter}),
        expectedCount,
      };
    }
    case 'target': {
      requireOneLiteralSearch(filter, 'target');
      const query = nativeTargetQueryFromFilter(filter.all());
      return {
        resourceType: 'target',
        ...(query.filter === '' ? {} : {search: query.filter}),
        expectedCount,
      };
    }
    case 'user': {
      requireOneLiteralSearch(filter, 'user');
      const query = nativeUserManagementQueryFromFilter(filter.all());
      return {
        resourceType: 'user',
        ...(query.filter === '' ? {} : {search: query.filter}),
        expectedCount,
      };
    }
    default:
      return undefined;
  }
};

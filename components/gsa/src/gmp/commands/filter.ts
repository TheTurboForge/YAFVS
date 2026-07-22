/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type {EntityCommandParams} from 'gmp/commands/entity';
import HttpCommand from 'gmp/commands/http';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import type Filter from 'gmp/models/filter';
import {
  cloneNativeFilter,
  createNativeFilter,
  deleteNativeFilter,
  exportNativeFilterMetadata,
  fetchNativeFilter,
  patchNativeFilter,
} from 'gmp/native-api/filters';
import {resourceType, type EntityType} from 'gmp/utils/entity-type';

const requireNativeFilterApi = (http: Http) => {
  if (!canUseNativeApi(http)) {
    throw new Error('Native filter API is required for filter command');
  }
};

export class FilterCommand extends HttpCommand {
  constructor(http: Http) {
    super(http);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeFilterMetadata(this.http, id);
  }

  async get(
    {id}: EntityCommandParams,
    _options: {filter?: Filter | string} = {},
  ) {
    requireNativeFilterApi(this.http);
    return new Response(await fetchNativeFilter(this.http, id));
  }

  async create(args: {
    term: string;
    name: string;
    type: EntityType;
    comment?: string;
  }) {
    const {term, name, type, comment = ''} = args;
    const filterType = resourceType(type);
    requireNativeFilterApi(this.http);
    if (filterType === undefined) {
      throw new Error(
        'Native filter create received unsupported resource type',
      );
    }
    return await createNativeFilter(this.http, {
      term,
      name,
      filterType,
      comment,
    });
  }

  async clone({id}: EntityCommandParams) {
    requireNativeFilterApi(this.http);
    return await cloneNativeFilter(this.http, id);
  }

  async delete({id}: EntityCommandParams) {
    requireNativeFilterApi(this.http);
    await deleteNativeFilter(this.http, id);
  }

  async save(args: {
    id: string;
    term: string;
    name: string;
    type: EntityType;
    comment?: string;
  }) {
    const {id, term, name, type, comment = ''} = args;
    const filterType = resourceType(type);
    requireNativeFilterApi(this.http);
    if (filterType === undefined) {
      throw new Error('Native filter save received unsupported resource type');
    }
    return patchNativeFilter(this.http, {
      id,
      term,
      name,
      filterType,
      comment,
    });
  }
}

export default FilterCommand;

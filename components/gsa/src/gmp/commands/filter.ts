/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand from 'gmp/commands/entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import {type XmlResponseData} from 'gmp/http/transform/fast-xml';
import logger from 'gmp/log';
import Filter, {type FilterModelElement} from 'gmp/models/filter';
import {cloneNativeFilter, createNativeFilter} from 'gmp/native-api/filters';
import {resourceType, type EntityType} from 'gmp/utils/entity-type';

interface GetFilterResponseData extends XmlResponseData {
  get_filter?: {
    get_filters_response?: {
      filter?: FilterModelElement;
    };
  };
}

const log = logger.getLogger('gmp.commands.filters');

export class FilterCommand extends EntityCommand<Filter, FilterModelElement> {
  constructor(http: Http) {
    super(http, 'filter', Filter);
  }

  async create(args: {
    term: string;
    name: string;
    type: EntityType;
    comment?: string;
  }) {
    const {term, name, type, comment = ''} = args;
    const filterType = resourceType(type);
    if (filterType !== undefined && canUseNativeApi(this.http)) {
      try {
        return await createNativeFilter(this.http, {
          term,
          name,
          filterType,
          comment,
        });
      } catch (error) {
        log.debug('Native filter create failed, falling back to GMP', error);
      }
    }

    const data = {
      cmd: 'create_filter',
      term,
      name,
      resource_type: filterType,
      comment,
    };
    log.debug('Creating new filter', args, data);
    return this.action(data);
  }

  async clone({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      try {
        return await cloneNativeFilter(this.http, id);
      } catch (error) {
        log.debug('Native filter clone failed, falling back to GMP', error);
      }
    }
    return super.clone({id});
  }

  save(args: {
    id: string;
    term: string;
    name: string;
    type: EntityType;
    comment?: string;
  }) {
    const {id, term, name, type, comment = ''} = args;
    const data = {
      cmd: 'save_filter',
      comment,
      id,
      name,
      resource_type: resourceType(type),
      term,
    };
    log.debug('Saving filter', args, data);
    return this.action(data);
  }

  getElementFromRoot(root: XmlResponseData): FilterModelElement {
    return (
      (root as GetFilterResponseData).get_filter?.get_filters_response
        ?.filter ?? ({} as FilterModelElement)
    );
  }
}

export default FilterCommand;

/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {canUseNativeApi} from 'gmp/commands/native';
import EntityCommand, {type EntityCommandParams} from 'gmp/commands/entity';
import type {HttpCommandOptions} from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import logger from 'gmp/log';
import type Filter from 'gmp/models/filter';
import {filterString} from 'gmp/models/filter/utils';
import {type Element} from 'gmp/models/model';
import Tag, {type TagElement} from 'gmp/models/tag';
import {
  cloneNativeTag,
  createNativeTag,
  deleteNativeTag,
  exportNativeTagMetadata,
  fetchNativeTag,
  patchNativeTag,
  updateNativeTagResources,
} from 'gmp/native-api/tags';
import {NO_VALUE, parseYesNo, YES_VALUE} from 'gmp/parser';
import {resourceType, type EntityType} from 'gmp/utils/entity-type';

interface TagCommandCreateParams {
  active: boolean;
  comment?: string;
  filter?: Filter | string;
  name: string;
  resourceIds?: string[];
  resourceType: EntityType;
  value?: string;
}

interface TagCommandSaveParams extends TagCommandCreateParams {
  id: string;
  resourcesAction?: 'add' | 'remove' | 'set';
}

const log = logger.getLogger('gmp.commands.tag');

const nativeTagDetailSupportsFilter = (filter?: Filter | string): boolean => {
  const value = filterString(filter);
  return filter === undefined || value === 'resources=1' || value === 'alerts=1';
};

class TagCommand extends EntityCommand<Tag, TagElement> {
  constructor(http: Http) {
    super(http, 'tag', Tag);
  }

  getElementFromRoot(root: Element): TagElement {
    // @ts-expect-error
    return root.get_tag.get_tags_response.tag;
  }

  async get(
    {id}: EntityCommandParams,
    {filter, ...options}: {filter?: Filter | string} & HttpCommandOptions = {},
  ) {
    if (canUseNativeApi(this.http)) {
      if (nativeTagDetailSupportsFilter(filter)) {
        return new Response(await fetchNativeTag(this.http, id));
      }
      throw new Error('Native tag detail filter is not supported');
    }
    return super.get({id}, {filter, ...options});
  }

  async create({
    active,
    comment = '',
    filter,
    name,
    resourceIds = [],
    resourceType: resourceTypeValue,
    value = '',
  }: TagCommandCreateParams) {
    const rawFilter = filterString(filter);
    const nativeFilter = rawFilter ?? '';
    if (canUseNativeApi(this.http)) {
      if (nativeFilter !== '') {
        throw new Error('Native tag create with filters is not supported');
      }
      return await createNativeTag(this.http, {
        active,
        comment,
        name,
        resourceIds,
        resourceType: resourceTypeValue,
        value,
      });
    }
    const data = {
      cmd: 'create_tag',
      filter: rawFilter,
      tag_name: name,
      tag_value: value,
      active: parseYesNo(active),
      comment,
      'resource_ids:': resourceIds.length > 0 ? resourceIds : undefined,
      resource_type: resourceType(resourceTypeValue),
    };
    log.debug('Creating new tag', data);
    return this.action(data);
  }

  async save({
    id,
    name,
    comment = '',
    active,
    filter,
    resourceIds = [],
    resourceType: resourceTypeValue,
    resourcesAction,
    value = '',
  }: TagCommandSaveParams) {
    const rawFilter = filterString(filter);
    if (canUseNativeApi(this.http)) {
      if (rawFilter !== undefined) {
        throw new Error('Native tag save with filters is not supported');
      }
      if (resourceIds.length === 0 && resourcesAction === undefined) {
        return patchNativeTag(this.http, id, {
          active,
          comment,
          name,
          value,
        });
      }
      if (
        resourceIds.length > 0 &&
        (resourcesAction === 'add' ||
          resourcesAction === 'remove' ||
          resourcesAction === 'set')
      ) {
        return updateNativeTagResources(this.http, id, {
          action: resourcesAction,
          resourceIds,
        });
      }
      throw new Error(
        'Native tag resource updates require explicit add, remove, or set action',
      );
    }

    const data = {
      cmd: 'save_tag',
      id,
      tag_name: name,
      tag_value: value,
      comment,
      active: parseYesNo(active),
      filter: rawFilter,
      'resource_ids:': resourceIds.length > 0 ? resourceIds : undefined,
      resource_type: resourceType(resourceTypeValue),
      resources_action: resourcesAction,
    };
    log.debug('Saving tag', data);
    return this.action(data);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeTagMetadata(this.http, id);
  }

  async enable({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      return patchNativeTag(this.http, id, {active: true});
    }
    const data = {
      cmd: 'toggle_tag',
      enable: YES_VALUE,
      id,
    };
    log.debug('Enabling tag', data);
    return this.httpPostWithTransform(data);
  }

  async disable({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      return patchNativeTag(this.http, id, {active: false});
    }
    const data = {
      cmd: 'toggle_tag',
      enable: NO_VALUE,
      id,
    };
    log.debug('Disabling tag', data);
    return this.httpPostWithTransform(data);
  }

  async clone({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      return await cloneNativeTag(this.http, id);
    }
    return super.clone({id});
  }

  async delete({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      await deleteNativeTag(this.http, id);
      return;
    }
    return super.delete({id});
  }
}

export default TagCommand;

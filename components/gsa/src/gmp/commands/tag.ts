/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {canUseNativeApi} from 'gmp/commands/native';
import EntityCommand, {type EntityCommandParams} from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import logger from 'gmp/log';
import type Filter from 'gmp/models/filter';
import {filterString} from 'gmp/models/filter/utils';
import {type Element} from 'gmp/models/model';
import Tag, {type TagElement} from 'gmp/models/tag';
import {
  cloneNativeTag,
  createNativeTag,
  deleteNativeTag,
  patchNativeTag,
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

class TagCommand extends EntityCommand<Tag, TagElement> {
  constructor(http: Http) {
    super(http, 'tag', Tag);
  }

  getElementFromRoot(root: Element): TagElement {
    // @ts-expect-error
    return root.get_tag.get_tags_response.tag;
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
    if (
      canUseNativeApi(this.http) &&
      resourceIds.length === 0 &&
      nativeFilter === ''
    ) {
      try {
        return await createNativeTag(this.http, {
          active,
          comment,
          name,
          resourceType: resourceTypeValue,
          value,
        });
      } catch (err) {
        log.error('Native tag create failed, falling back to GMP', name, err);
      }
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
    if (
      canUseNativeApi(this.http) &&
      resourceIds.length === 0 &&
      rawFilter === undefined &&
      resourcesAction === undefined
    ) {
      return patchNativeTag(this.http, id, {
        active,
        comment,
        name,
        value,
      });
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
      try {
        return await cloneNativeTag(this.http, id);
      } catch (err) {
        log.error('Native tag clone failed, falling back to GMP', id, err);
      }
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

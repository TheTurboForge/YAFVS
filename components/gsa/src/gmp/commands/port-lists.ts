/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntitiesCommand from 'gmp/commands/entities';
import type {EntityCommandParams} from 'gmp/commands/entity';
import type {
  HttpCommandInputParams,
  HttpCommandOptions,
} from 'gmp/commands/http';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import EntityCommand from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import logger from 'gmp/log';
import {type Element} from 'gmp/models/model';
import PortList, {type PortListElement} from 'gmp/models/port-list';
import {
  cloneNativePortList,
  fetchNativePortLists,
  nativePortListsQueryFromFilter,
} from 'gmp/native-api/port-lists';
import {NO_VALUE, YES_VALUE} from 'gmp/parser';

export type FromFile = typeof FROM_FILE | typeof NOT_FROM_FILE;

export interface PortListCommandCreateParams {
  name: string;
  comment?: string;
  fromFile?: FromFile;
  portRange?: string;
  file?: File;
}

export interface PortListCommandSaveParams {
  id: string;
  name: string;
  comment?: string;
}

interface PortListCommandCreatePortRangeParams {
  portListId: string;
  portRangeStart: number;
  portRangeEnd: number;
  portType: string;
}

interface PortListCommandDeletePortRangeParams {
  id: string;
  portListId: string;
}

interface PortListCommandImportParams {
  xmlFile?: File;
}

const log = logger.getLogger('gmp.commands.portlists');

export const FROM_FILE = YES_VALUE;
export const NOT_FROM_FILE = NO_VALUE;

export class PortListCommand extends EntityCommand<PortList, PortListElement> {
  constructor(http: Http) {
    super(http, 'port_list', PortList);
  }

  create({
    name,
    comment = '',
    fromFile,
    portRange,
    file,
  }: PortListCommandCreateParams) {
    log.debug('Creating new port list', {
      name,
      comment,
      from_file: fromFile,
      port_range: portRange,
      file,
    });
    return this.entityAction({
      cmd: 'create_port_list',
      name,
      comment,
      from_file: fromFile,
      port_range: portRange,
      file,
    });
  }

  save({id, name, comment = ''}: PortListCommandSaveParams) {
    log.debug('Saving port list', {id, name, comment});
    return this.action({
      cmd: 'save_port_list',
      comment,
      id,
      name,
    });
  }

  async clone({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      try {
        return await cloneNativePortList(this.http, id);
      } catch (error) {
        log.debug('Native port list clone failed, falling back to GMP', error);
      }
    }
    return super.clone({id});
  }

  createPortRange({
    portListId,
    portRangeStart,
    portRangeEnd,
    portType,
  }: PortListCommandCreatePortRangeParams) {
    return this.action({
      cmd: 'create_port_range',
      id: portListId,
      port_range_start: portRangeStart,
      port_range_end: portRangeEnd,
      port_type: portType,
    });
  }

  async deletePortRange({
    id,
    portListId,
  }: PortListCommandDeletePortRangeParams) {
    await this.httpPostWithTransform({
      cmd: 'delete_port_range',
      port_range_id: id,
      no_redirect: 1,
    });
    return await this.get({id: portListId});
  }

  import({xmlFile}: PortListCommandImportParams) {
    log.debug('Importing port list', {xml_file: xmlFile});
    return this.entityAction({
      cmd: 'import_port_list',
      xml_file: xmlFile,
    });
  }

  getElementFromRoot(root: Element): PortListElement {
    // @ts-expect-error
    return root.get_port_list.get_port_lists_response.port_list;
  }
}

export class PortListsCommand extends EntitiesCommand<PortList> {
  constructor(http: Http) {
    super(http, 'port_list', PortList);
  }

  async get(
    params: HttpCommandInputParams = {},
    options?: HttpCommandOptions,
  ) {
    if (!canUseNativeApi(this.http)) {
      return super.get(params, options);
    }

    const filter = filterFromCommandParams(params);
    const nativeResponse = await fetchNativePortLists(
      this.http,
      nativePortListsQueryFromFilter(filter),
    );

    return new Response(nativeResponse.portLists, {
      filter,
      counts: nativeResponse.counts,
    });
  }

  async getAll(
    params: HttpCommandInputParams = {},
    options?: HttpCommandOptions,
  ) {
    if (!canUseNativeApi(this.http)) {
      return super.getAll(params, options);
    }

    const filter = filterFromCommandParams(params).all();
    const portLists: PortList[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; portLists.length < total; page += 1) {
      const nativeResponse = await fetchNativePortLists(this.http, {
        ...nativePortListsQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      portLists.push(...nativeResponse.portLists);
      total = nativeResponse.page.total;
      if (nativeResponse.portLists.length === 0) {
        break;
      }
    }

    return new Response(
      portLists,
      nativeCollectionMeta(
        filter,
        portLists,
        Number.isFinite(total) ? total : 0,
      ),
    );
  }

  getEntitiesResponse(root: Element) {
    // @ts-expect-error
    return root.get_port_lists.get_port_lists_response;
  }
}

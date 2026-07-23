/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * YAFVS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {
  type ModelClass,
  type InfoEntitiesFilterFunc,
} from 'gmp/collection/parser';
import EntitiesCommand, {type EntitiesMeta} from 'gmp/commands/entities';
import type {
  HttpCommandInputParams,
  HttpCommandOptions,
} from 'gmp/commands/http';
import {type InfoType} from 'gmp/commands/info-entity';
import type Http from 'gmp/http/http';
import type Response from 'gmp/http/response';
import type {XmlMeta} from 'gmp/http/transform/fast-xml';
import Filter from 'gmp/models/filter';
import {type default as Model} from 'gmp/models/model';

class InfoEntitiesCommand<
  TModel extends Model,
> extends EntitiesCommand<TModel> {
  constructor(
    http: Http,
    infoType: InfoType,
    model: ModelClass<TModel>,
    _entitiesFilterFunc: InfoEntitiesFilterFunc,
  ) {
    super(http, 'info', model);
    this.setDefaultParam('info_type', infoType);
  }

  protected getEntitiesResponse(): never {
    throw new Error('Raw catalog response parsing is not supported');
  }

  async get(
    _params: HttpCommandInputParams = {},
    _options?: HttpCommandOptions,
  ): Promise<Response<TModel[], EntitiesMeta>> {
    throw new Error('Catalog list reads require a native API implementation');
  }

  async getAll(
    _params: HttpCommandInputParams = {},
    _options?: HttpCommandOptions,
  ): Promise<Response<TModel[], EntitiesMeta>> {
    throw new Error('Catalog list reads require a native API implementation');
  }

  async export(_entities: TModel[]): Promise<Response<string>> {
    throw new Error(
      'Catalog metadata export requires a native API implementation',
    );
  }

  async exportByIds(_ids: string[]): Promise<Response<string>> {
    throw new Error(
      'Catalog metadata export requires a native API implementation',
    );
  }

  async exportByFilter(_filter: Filter): Promise<Response<string>> {
    throw new Error(
      'Catalog metadata export requires a native API implementation',
    );
  }

  async delete(_entities: TModel[]): Promise<Response<TModel[], XmlMeta>> {
    throw new Error('Catalog entries cannot be deleted through this command');
  }

  async deleteByIds(_ids: string[]): Promise<Response<string[], XmlMeta>> {
    throw new Error('Catalog entries cannot be deleted through this command');
  }

  async deleteByFilter(_filter: Filter): Promise<Response<TModel[], XmlMeta>> {
    throw new Error('Catalog entries cannot be deleted through this command');
  }
}

export default InfoEntitiesCommand;

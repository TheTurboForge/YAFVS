/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * YAFVS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {type ModelClass} from 'gmp/collection/parser';
import EntityCommand, {type EntityCommandParams} from 'gmp/commands/entity';
import type Http from 'gmp/http/http';
import type Response from 'gmp/http/response';
import type {XmlMeta} from 'gmp/http/transform/fast-xml';
import type Model from 'gmp/models/model';

export type InfoType = 'nvt' | 'cve' | 'cpe' | 'dfn_cert_adv' | 'cert_bund_adv';

class InfoEntityCommand<TModel extends Model> extends EntityCommand<TModel> {
  constructor(http: Http, _infoType: InfoType, model: ModelClass<TModel>) {
    super(http, 'info', model);
  }

  protected getElementFromRoot(): never {
    throw new Error('Raw catalog response parsing is not supported');
  }

  async get(_params: EntityCommandParams): Promise<Response<TModel, XmlMeta>> {
    throw new Error('Catalog detail reads require a native API implementation');
  }

  async delete(_params: EntityCommandParams): Promise<void> {
    throw new Error('Catalog entries cannot be deleted through this command');
  }

  async export(_params: EntityCommandParams): Promise<Response<string>> {
    throw new Error(
      'Catalog metadata export requires a native API implementation',
    );
  }
}

export default InfoEntityCommand;

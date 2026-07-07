/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand, {type EntityCommandParams} from 'gmp/commands/entity';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import type Response from 'gmp/http/response';
import {type XmlMeta} from 'gmp/http/transform/fast-xml';
import logger from 'gmp/log';
import {type Element} from 'gmp/models/model';
import Scanner, {
  type ScannerElement,
  type ScannerType,
} from 'gmp/models/scanner';
import {
  exportNativeScannerMetadata,
  patchNativeScanner,
} from 'gmp/native-api/scanners';

export interface ScannerCommandCreateParams {
  name: string;
  caCertificate?: File;
  comment?: string;
  credentialId?: string;
  host: string;
  port: number | '';
  type: ScannerType;
}

export interface ScannerCommandSaveParams extends ScannerCommandCreateParams {
  id: string;
}

export interface ScannerCommandMetadataSaveParams {
  id: string;
  name: string;
  comment?: string;
}

type ScannerCommandSaveArgs =
  | ScannerCommandSaveParams
  | ScannerCommandMetadataSaveParams;

interface ScannerCommandVerifyParams {
  id: string;
}

const log = logger.getLogger('gmp.commands.scanner');

const SCANNER_METADATA_SAVE_KEYS = new Set(['id', 'name', 'comment']);

const isScannerMetadataOnlySave = (
  args: ScannerCommandSaveArgs,
): args is ScannerCommandMetadataSaveParams => {
  const keys = Object.keys(args);
  return (
    keys.every(key => SCANNER_METADATA_SAVE_KEYS.has(key)) &&
    typeof args.id === 'string' &&
    typeof args.name === 'string' &&
    (args.comment === undefined || typeof args.comment === 'string')
  );
};

class ScannerCommand extends EntityCommand<Scanner, ScannerElement> {
  constructor(http: Http) {
    super(http, 'scanner', Scanner);
  }

  getElementFromRoot(root: Element): ScannerElement {
    // @ts-expect-error
    return root.get_scanner.get_scanners_response.scanner;
  }

  async get(
    {id}: EntityCommandParams,
    {filter, details, ...options}: {filter?: string; details?: boolean} = {},
  ): Promise<Response<Scanner, XmlMeta>> {
    const response = await this.httpGetWithTransform(
      {id, filter, details: details ? '1' : '0'},
      options,
    );
    return this.transformResponseToModel(response);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeScannerMetadata(this.http, id);
  }

  create({
    name,
    caCertificate,
    comment = '',
    credentialId,
    host,
    port,
    type,
  }: ScannerCommandCreateParams) {
    const data = {
      cmd: 'create_scanner',
      ca_pub: caCertificate,
      comment,
      credential_id: credentialId,
      name,
      port,
      scanner_host: host,
      scanner_type: type,
    };
    log.debug('Creating new scanner', data);
    return this.entityAction(data);
  }

  save(args: ScannerCommandSaveArgs) {
    if (canUseNativeApi(this.http) && isScannerMetadataOnlySave(args)) {
      return patchNativeScanner(this.http, {
        id: args.id,
        name: args.name,
        comment: args.comment,
      });
    }

    const {
      id,
      name,
      caCertificate,
      comment = '',
      credentialId,
      host,
      port,
      type,
    } = args as ScannerCommandSaveParams;
    const data = {
      cmd: 'save_scanner',
      // send empty string if caCertificate is undefined to remove existing CA cert
      ca_pub: caCertificate ?? '',
      comment,
      // send empty string if credentialId is undefined to remove existing credential
      credential_id: credentialId ?? '',
      id,
      name,
      port,
      scanner_host: host,
      scanner_type: type,
    };
    log.debug('Saving scanner', data);
    return this.action(data);
  }

  verify({id}: ScannerCommandVerifyParams) {
    return this.action({
      cmd: 'verify_scanner',
      id,
    });
  }
}

export default ScannerCommand;

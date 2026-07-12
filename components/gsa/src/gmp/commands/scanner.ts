/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand, {type EntityCommandParams} from 'gmp/commands/entity';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import {type XmlMeta} from 'gmp/http/transform/fast-xml';
import {filterString} from 'gmp/models/filter/utils';
import {type Element} from 'gmp/models/model';
import Scanner, {
  type ScannerElement,
  type ScannerType,
} from 'gmp/models/scanner';
import {
  exportNativeScannerMetadata,
  fetchNativeScanner,
  createNativeScanner,
  patchNativeScanner,
  replaceNativeScannerConfiguration,
  verifyNativeScanner,
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

export type ScannerCommandSaveArgs =
  | ScannerCommandSaveParams
  | ScannerCommandMetadataSaveParams;

interface ScannerCommandVerifyParams {
  id: string;
}

const nativeScannerDetailSupportsFilter = (filter?: string): boolean => {
  const value = filterString(filter);
  return filter === undefined || value === 'tasks=1' || value === 'alerts=1';
};

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
    if (
      details !== true &&
      canUseNativeApi(this.http) &&
      nativeScannerDetailSupportsFilter(filter)
    ) {
      const nativeResponse = await fetchNativeScanner(this.http, id);
      return new Response(nativeResponse.scanner);
    }

    const response = await this.httpGetWithTransform(
      {id, filter, details: details ? '1' : '0'},
      options,
    );
    return this.transformResponseToModel(response);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeScannerMetadata(this.http, id);
  }

  async create({
    name,
    caCertificate,
    comment = '',
    credentialId,
    host,
    port,
    type,
  }: ScannerCommandCreateParams) {
    return createNativeScanner(this.http, {
      comment,
      credentialId,
      caPub: await caCertificate?.text(),
      host,
      name,
      port,
      scannerType: Number(type),
    });
  }

  async save(args: ScannerCommandSaveArgs) {
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
    return replaceNativeScannerConfiguration(this.http, id, {
      comment,
      credentialId,
      caPub: await caCertificate?.text(),
      host,
      name,
      port,
      scannerType: Number(type),
    });
  }

  verify({id}: ScannerCommandVerifyParams) {
    if (canUseNativeApi(this.http)) {
      return verifyNativeScanner(this.http, id);
    }
    return this.action({
      cmd: 'verify_scanner',
      id,
    });
  }
}

export default ScannerCommand;

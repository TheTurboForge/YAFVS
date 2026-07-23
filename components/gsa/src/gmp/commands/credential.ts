/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand from 'gmp/commands/entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Credential, {
  type CredentialType,
  type CredentialElement,
  type SNMPAuthAlgorithmType,
  type SNMPPrivacyAlgorithmType,
} from 'gmp/models/credential';
import {type Element} from 'gmp/models/model';
import {
  cloneNativeCredential,
  exportNativeCredentialMetadata,
  fetchNativeCredential,
  patchNativeCredential,
} from 'gmp/native-api/credentials';
import {parseYesNo} from 'gmp/parser';
import {isDefined} from 'gmp/utils/identity';

export type CredentialDownloadFormat = 'pem' | 'key' | 'rpm' | 'deb' | 'exe';

interface CredentialCommandBaseArgs {
  authAlgorithm?: SNMPAuthAlgorithmType;
  autogenerate?: boolean;
  certificate?: File | null;
  comment?: string;
  community?: string;
  credentialLogin?: string;
  credentialType?: CredentialType;
  name: string;
  passphrase?: string;
  password?: string;
  privacyAlgorithm?: SNMPPrivacyAlgorithmType;
  privacyPassword?: string;
  privateKey?: File | null;
  publicKey?: File | null;
}

interface CredentialCommandKrb5Fields {
  kdcs?: string[];
  realm?: string;
}

// Create operation interfaces
type CredentialCommandCreateArgs = CredentialCommandBaseArgs;

interface CredentialCommandKrb5Args
  extends CredentialCommandBaseArgs, CredentialCommandKrb5Fields {}

// Save operation interfaces (using utility types)
type CredentialCommandSaveArgs = Omit<
  CredentialCommandBaseArgs,
  'autogenerate'
> & {id: string};

type CredentialCommandSaveKrb5Args = CredentialCommandSaveArgs &
  CredentialCommandKrb5Fields;

const saveFile = (file: File | undefined | null): File | undefined | string => {
  if (file === null) {
    // remove file from backend
    return '';
  }
  if (!isDefined(file) || file.size === 0) {
    // keep existing file on backend
    return undefined;
  }
  return file;
};

const CREDENTIAL_METADATA_SAVE_KEYS = new Set(['id', 'name', 'comment']);

const isCredentialMetadataOnlySave = (
  args: CredentialCommandSaveArgs,
): boolean =>
  Object.keys(args).every(key => CREDENTIAL_METADATA_SAVE_KEYS.has(key)) &&
  typeof args.id === 'string' &&
  typeof args.name === 'string' &&
  (args.comment === undefined || typeof args.comment === 'string');

class CredentialCommand extends EntityCommand<
  Credential,
  CredentialElement,
  Element
> {
  constructor(http: Http) {
    super(http, 'credential', Credential);
  }

  async clone({id}: EntityCommandParams) {
    return cloneNativeCredential(this.http, id);
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeCredentialMetadata(this.http, id);
  }

  async get({id}: EntityCommandParams) {
    const credential = await fetchNativeCredential(this.http, id);
    return new Response(credential);
  }

  private createBase({
    name,
    comment,
    autogenerate,
    community,
    credentialLogin,
    password,
    passphrase,
    privacyPassword,
    authAlgorithm,
    certificate,
    credentialType,
    privacyAlgorithm,
    privateKey,
    publicKey,
  }: CredentialCommandBaseArgs) {
    return {
      cmd: 'create_credential',
      auth_algorithm: authAlgorithm,
      autogenerate: parseYesNo(autogenerate),
      certificate,
      comment,
      community,
      credential_login: credentialLogin,
      credential_type: credentialType,
      lsc_password: password,
      name,
      passphrase,
      privacy_algorithm: privacyAlgorithm,
      privacy_password: privacyPassword,
      private_key: privateKey,
      public_key: publicKey,
    };
  }

  create(args: CredentialCommandCreateArgs) {
    const baseData = this.createBase(args);
    return this.action(baseData);
  }

  createKrb5(args: CredentialCommandKrb5Args) {
    const baseData = this.createBase(args);

    return this.action({
      ...baseData,
      realm: args.realm,
      'kdcs:': args.kdcs?.length ? args.kdcs : '',
    });
  }

  private saveBase({
    authAlgorithm,
    certificate,
    comment,
    community,
    credentialLogin,
    credentialType,
    id,
    name,
    passphrase,
    password,
    privacyAlgorithm,
    privacyPassword,
    privateKey,
    publicKey,
  }: CredentialCommandSaveArgs) {
    return {
      cmd: 'save_credential',
      auth_algorithm: authAlgorithm,
      certificate: saveFile(certificate),
      comment,
      community,
      credential_login: credentialLogin,
      credential_type: credentialType,
      credential_id: id,
      name,
      passphrase,
      password,
      privacy_algorithm: privacyAlgorithm,
      privacy_password: privacyPassword,
      private_key: saveFile(privateKey),
      public_key: saveFile(publicKey),
    };
  }

  async save(args: CredentialCommandSaveArgs) {
    if (canUseNativeApi(this.http) && isCredentialMetadataOnlySave(args)) {
      return patchNativeCredential(this.http, {
        id: args.id,
        name: args.name,
        comment: args.comment,
      });
    }

    const baseData = this.saveBase(args);
    return this.action(baseData);
  }

  saveKrb5(args: CredentialCommandSaveKrb5Args) {
    const baseData = this.saveBase(args);

    return this.action({
      ...baseData,
      realm: args.realm,
      'kdcs:': args.kdcs?.length ? args.kdcs : '',
    });
  }

  async download({id}, format: CredentialDownloadFormat = 'pem') {
    return this.httpRequestWithRejectionTransform<ArrayBuffer>('get', {
      args: {
        cmd: 'download_credential',
        package_format: format,
        credential_id: id,
      },
      responseType: 'arraybuffer',
    });
  }

  getElementFromRoot(root: Element): CredentialElement {
    // @ts-expect-error
    return root.get_credential.get_credentials_response.credential;
  }
}

export default CredentialCommand;

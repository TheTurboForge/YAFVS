/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand, {type EntityCommandParams} from 'gmp/commands/entity';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Credential, {
  type CredentialType,
  type CredentialElement,
  type SNMPAuthAlgorithmType,
  type SNMPPrivacyAlgorithmType,
  SNMP_CREDENTIAL_TYPE,
  USERNAME_PASSWORD_CREDENTIAL_TYPE,
  USERNAME_SSH_KEY_CREDENTIAL_TYPE,
} from 'gmp/models/credential';
import {type Element} from 'gmp/models/model';
import {
  cloneNativeCredential,
  createNativeCredential,
  deleteNativeCredential,
  exportNativeCredentialMetadata,
  fetchNativeCredential,
  fetchNativeCredentialCertificate,
  fetchNativeCredentialPublicKey,
  patchNativeCredential,
} from 'gmp/native-api/credentials';
import {parseYesNo} from 'gmp/parser';
import {isDefined} from 'gmp/utils/identity';

export type CredentialDownloadFormat = 'pem' | 'key';

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
type CredentialCommandSaveArgs = CredentialCommandBaseArgs & {id: string};

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

const isCredentialMetadataOnlySave = (
  args: CredentialCommandSaveKrb5Args,
): boolean => {
  if (
    typeof args.id !== 'string' ||
    typeof args.name !== 'string' ||
    (args.comment !== undefined && typeof args.comment !== 'string') ||
    (args.autogenerate !== undefined && args.autogenerate !== false)
  ) {
    return false;
  }

  const mutationKeys: (keyof CredentialCommandSaveKrb5Args)[] = [
    'authAlgorithm',
    'certificate',
    'community',
    'credentialLogin',
    'kdcs',
    'passphrase',
    'password',
    'privacyPassword',
    'privateKey',
    'publicKey',
    'realm',
  ];

  const metadataOrContextKeys = new Set([
    'id',
    'name',
    'comment',
    'credentialType',
    'autogenerate',
    'privacyAlgorithm',
    ...mutationKeys,
  ]);

  if (
    mutationKeys.some(key => args[key] !== undefined) ||
    Object.entries(args).some(
      ([key, value]) => value !== undefined && !metadataOrContextKeys.has(key),
    )
  ) {
    return false;
  }

  return !(
    args.credentialType === SNMP_CREDENTIAL_TYPE &&
    args.privacyAlgorithm !== undefined
  );
};

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

  async delete({id}: EntityCommandParams) {
    await deleteNativeCredential(this.http, id);
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

  async create(args: CredentialCommandCreateArgs) {
    if (
      canUseNativeApi(this.http) &&
      args.autogenerate !== true &&
      args.credentialType === USERNAME_PASSWORD_CREDENTIAL_TYPE
    ) {
      return createNativeCredential(this.http, {
        name: args.name,
        comment: args.comment,
        login: args.credentialLogin ?? '',
        type: USERNAME_PASSWORD_CREDENTIAL_TYPE,
        password: args.password ?? '',
      });
    }
    if (
      canUseNativeApi(this.http) &&
      args.autogenerate !== true &&
      args.credentialType === USERNAME_SSH_KEY_CREDENTIAL_TYPE
    ) {
      return createNativeCredential(this.http, {
        name: args.name,
        comment: args.comment,
        login: args.credentialLogin ?? '',
        type: USERNAME_SSH_KEY_CREDENTIAL_TYPE,
        passphrase: args.passphrase,
        privateKey: args.privateKey ? await args.privateKey.text() : '',
      });
    }
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

  async saveKrb5(args: CredentialCommandSaveKrb5Args) {
    if (canUseNativeApi(this.http) && isCredentialMetadataOnlySave(args)) {
      return patchNativeCredential(this.http, {
        id: args.id,
        name: args.name,
        comment: args.comment,
      });
    }

    const baseData = this.saveBase(args);

    return this.action({
      ...baseData,
      realm: args.realm,
      'kdcs:': args.kdcs?.length ? args.kdcs : '',
    });
  }

  async download({id}, format: CredentialDownloadFormat = 'pem') {
    if (format === 'key') {
      return new Response(await fetchNativeCredentialPublicKey(this.http, id));
    }
    return new Response(await fetchNativeCredentialCertificate(this.http, id));
  }

  getElementFromRoot(root: Element): CredentialElement {
    // @ts-expect-error
    return root.get_credential.get_credentials_response.credential;
  }
}

export default CredentialCommand;

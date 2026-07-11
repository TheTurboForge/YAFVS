/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand from 'gmp/commands/entity';
import type {EntityCommandParams} from 'gmp/commands/entity';
import {feedStatusRejection} from 'gmp/native-api/feeds';
import {canUseNativeApi} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import type Filter from 'gmp/models/filter';
import {filterString} from 'gmp/models/filter/utils';
import Target, {
  ARP_PING,
  CONSIDER_ALIVE,
  ICMP_PING,
  SCAN_CONFIG_DEFAULT,
  TCP_ACK,
  TCP_SYN,
  type AliveTest,
} from 'gmp/models/target';
import {
  cloneNativeTarget,
  createNativeTarget,
  deleteNativeTarget,
  exportNativeTargetMetadata,
  fetchNativeTarget,
  patchNativeTarget,
  type NativeTargetCredentialPatchArgs,
  type NativeTargetCredentialsPatchArgs,
  type NativeTargetCreateArgs,
  type NativeTargetPatchArgs,
} from 'gmp/native-api/targets';
import {parseYesNo} from 'gmp/parser';
import {isDefined} from 'gmp/utils/identity';
import {UNSET_VALUE} from 'web/utils/Render';

export type TargetSource = 'manual' | 'file' | 'asset_hosts';
export type TargetExcludeSource = 'manual' | 'file';

interface TargetCommandCreateParams {
  aliveTests?: AliveTest[];
  allowSimultaneousIPs?: boolean;
  comment?: string;
  esxiCredentialId?: string;
  excludeFile?: File;
  excludeHosts?: string;
  file?: File;
  hosts?: string;
  hostsFilter?: Filter;
  krb5CredentialId?: string;
  name: string;
  port?: number;
  portListId?: string;
  reverseLookupOnly?: boolean;
  reverseLookupUnify?: boolean;
  smbCredentialId?: string;
  snmpCredentialId?: string;
  sshCredentialId?: string;
  sshElevateCredentialId?: string;
  targetExcludeSource?: TargetExcludeSource;
  targetSource?: TargetSource;
}

export interface TargetCommandSaveParams extends TargetCommandCreateParams {
  id: string;
}

type TargetCommandSaveArgs = TargetCommandSaveParams;

const NATIVE_TARGET_ALIVE_TESTS = new Set<AliveTest>([
  ARP_PING,
  CONSIDER_ALIVE,
  ICMP_PING,
  SCAN_CONFIG_DEFAULT,
  TCP_ACK,
  TCP_SYN,
]);

const isUnsetCredential = (id?: string) =>
  id === undefined || id === UNSET_VALUE;

const isValidSshPort = (port?: number): boolean =>
  port === undefined || (Number.isInteger(port) && port >= 1 && port <= 65535);

const looksLikeIpv4Range = (value: string) => {
  const [left, right] = value.split('-', 2);
  if (right === undefined) {
    return false;
  }
  return /^\d+\.\d+\.\d+\.\d+$/.test(left) && /^[\d.]+$/.test(right);
};

const looksLikeIpv4WithLeadingZero = (value: string) =>
  /^\d+\.\d+\.\d+\.\d+$/.test(value) &&
  value.split('.').some(part => part.length > 1 && part.startsWith('0'));

const isNativeTargetHostEntry = (value: string) =>
  value.length <= 4096 &&
  !/[\u0000-\u001F\u007F]/.test(value) &&
  !value.includes('/') &&
  !looksLikeIpv4Range(value) &&
  !looksLikeIpv4WithLeadingZero(value) &&
  /^[A-Za-z0-9._:-]+$/.test(value);

const parseNativeTargetHostList = (
  value: string | undefined,
  {allowEmpty = false}: {allowEmpty?: boolean} = {},
) => {
  if (value === undefined) {
    return undefined;
  }
  const entries = value
    .split(',')
    .map(entry => entry.trim())
    .filter(entry => entry.length > 0);
  if (entries.length === 0) {
    return allowEmpty ? [] : undefined;
  }
  return entries.every(isNativeTargetHostEntry)
    ? [...new Set(entries)]
    : undefined;
};

const canUseNativeTargetAliveTests = (
  aliveTests?: AliveTest[],
): aliveTests is AliveTest[] => {
  if (!Array.isArray(aliveTests) || aliveTests.length === 0) {
    return false;
  }
  if (
    !aliveTests.every(aliveTest => NATIVE_TARGET_ALIVE_TESTS.has(aliveTest))
  ) {
    return false;
  }
  if (
    aliveTests.includes(SCAN_CONFIG_DEFAULT) ||
    aliveTests.includes(CONSIDER_ALIVE)
  ) {
    return aliveTests.length === 1;
  }
  return true;
};

const nativeTargetCreateArgsFromParams = ({
  aliveTests,
  allowSimultaneousIPs,
  comment,
  esxiCredentialId,
  excludeFile,
  excludeHosts,
  file,
  hosts,
  hostsFilter,
  krb5CredentialId,
  name,
  port,
  portListId,
  reverseLookupOnly,
  reverseLookupUnify,
  smbCredentialId,
  snmpCredentialId,
  sshCredentialId,
  sshElevateCredentialId,
  targetExcludeSource,
  targetSource,
}: TargetCommandCreateParams): NativeTargetCreateArgs | undefined => {
  if (targetSource !== undefined && targetSource !== 'manual') {
    return undefined;
  }
  if (targetExcludeSource !== undefined && targetExcludeSource !== 'manual') {
    return undefined;
  }
  if (
    file !== undefined ||
    excludeFile !== undefined ||
    hostsFilter !== undefined
  ) {
    return undefined;
  }
  const hasCredentialInput = [
    esxiCredentialId,
    krb5CredentialId,
    smbCredentialId,
    snmpCredentialId,
    sshCredentialId,
    sshElevateCredentialId,
  ].some(id => !isUnsetCredential(id));
  if (port !== undefined && port !== 22 && !hasCredentialInput) {
    return undefined;
  }
  const credentials = nativeTargetCredentialsCreateFromParams({
    esxiCredentialId,
    krb5CredentialId,
    port,
    smbCredentialId,
    snmpCredentialId,
    sshCredentialId,
    sshElevateCredentialId,
  });
  if (credentials === undefined && hasCredentialInput) {
    return undefined;
  }
  if (
    !canUseNativeTargetAliveTests(aliveTests) ||
    typeof allowSimultaneousIPs !== 'boolean' ||
    typeof reverseLookupOnly !== 'boolean' ||
    typeof reverseLookupUnify !== 'boolean' ||
    typeof portListId !== 'string' ||
    portListId.length === 0
  ) {
    return undefined;
  }
  const nativeHosts = parseNativeTargetHostList(hosts);
  if (nativeHosts === undefined) {
    return undefined;
  }
  const nativeExcludeHosts = parseNativeTargetHostList(excludeHosts, {
    allowEmpty: true,
  });
  if (excludeHosts !== undefined && nativeExcludeHosts === undefined) {
    return undefined;
  }
  const excludedHosts = new Set(nativeExcludeHosts ?? []);
  if (nativeHosts.every(host => excludedHosts.has(host))) {
    return undefined;
  }
  return {
    name,
    comment,
    portListId,
    hosts: nativeHosts,
    ...(nativeExcludeHosts !== undefined
      ? {excludeHosts: nativeExcludeHosts}
      : {}),
    aliveTests,
    allowSimultaneousIPs,
    reverseLookupOnly,
    reverseLookupUnify,
    ...(credentials !== undefined ? {credentials} : {}),
  };
};

const nativeTargetCredentialsCreateFromParams = ({
  esxiCredentialId,
  krb5CredentialId,
  port,
  smbCredentialId,
  snmpCredentialId,
  sshCredentialId,
  sshElevateCredentialId,
}: Pick<
  TargetCommandCreateParams,
  | 'esxiCredentialId'
  | 'krb5CredentialId'
  | 'port'
  | 'smbCredentialId'
  | 'snmpCredentialId'
  | 'sshCredentialId'
  | 'sshElevateCredentialId'
>): NativeTargetCredentialsPatchArgs | undefined => {
  if (!isValidSshPort(port)) {
    return undefined;
  }
  if (port !== undefined && port !== 22 && isUnsetCredential(sshCredentialId)) {
    return undefined;
  }
  if (isUnsetCredential(sshCredentialId) && !isUnsetCredential(sshElevateCredentialId)) {
    return undefined;
  }
  const credentials: NativeTargetCredentialsPatchArgs = {
    ssh: nativeCredentialCreateFromId(sshCredentialId, port),
    sshElevate: nativeCredentialCreateFromId(sshElevateCredentialId),
    smb: nativeCredentialCreateFromId(smbCredentialId),
    esxi: nativeCredentialCreateFromId(esxiCredentialId),
    snmp: nativeCredentialCreateFromId(snmpCredentialId),
    krb5: nativeCredentialCreateFromId(krb5CredentialId),
  };
  return Object.values(credentials).some(value => value !== undefined)
    ? credentials
    : undefined;
};

const nativeCredentialCreateFromId = (
  id?: string,
  port?: number,
): NativeTargetCredentialPatchArgs | undefined => {
  if (isUnsetCredential(id)) {
    return undefined;
  }
  if (id.trim().length === 0) {
    return undefined;
  }
  return {
    id,
    ...(port !== undefined ? {port} : {}),
  };
};

const nativeCredentialPatchFromId = (
  id?: string,
  port?: number,
): NativeTargetCredentialPatchArgs | undefined => {
  if (id === undefined) {
    return undefined;
  }
  if (id === UNSET_VALUE) {
    return null;
  }
  if (id.trim().length === 0) {
    return undefined;
  }
  return {
    id,
    ...(port !== undefined ? {port} : {}),
  };
};

const nativeTargetCredentialsPatchFromParams = ({
  esxiCredentialId,
  krb5CredentialId,
  port,
  smbCredentialId,
  snmpCredentialId,
  sshCredentialId,
  sshElevateCredentialId,
}: TargetCommandSaveArgs): NativeTargetCredentialsPatchArgs | undefined => {
  if (!isValidSshPort(port)) {
    return undefined;
  }
  if (port !== undefined && sshCredentialId === undefined) {
    return undefined;
  }
  if (sshCredentialId === undefined && sshElevateCredentialId !== undefined) {
    return undefined;
  }
  if (
    sshCredentialId === UNSET_VALUE &&
    sshElevateCredentialId !== undefined &&
    sshElevateCredentialId !== UNSET_VALUE
  ) {
    return undefined;
  }
  const credentials: NativeTargetCredentialsPatchArgs = {
    ssh: nativeCredentialPatchFromId(sshCredentialId, port),
    sshElevate: nativeCredentialPatchFromId(sshElevateCredentialId),
    smb: nativeCredentialPatchFromId(smbCredentialId),
    esxi: nativeCredentialPatchFromId(esxiCredentialId),
    snmp: nativeCredentialPatchFromId(snmpCredentialId),
    krb5: nativeCredentialPatchFromId(krb5CredentialId),
  };
  return Object.values(credentials).some(value => value !== undefined)
    ? credentials
    : undefined;
};

const nativeTargetPatchArgsFromParams = ({
  aliveTests,
  allowSimultaneousIPs,
  comment,
  esxiCredentialId,
  excludeFile,
  excludeHosts,
  file,
  hosts,
  hostsFilter,
  id,
  krb5CredentialId,
  name,
  port,
  portListId,
  reverseLookupOnly,
  reverseLookupUnify,
  smbCredentialId,
  snmpCredentialId,
  sshCredentialId,
  sshElevateCredentialId,
  targetExcludeSource,
  targetSource,
}: TargetCommandSaveArgs): NativeTargetPatchArgs | undefined => {
  if (targetSource !== undefined && targetSource !== 'manual') {
    return undefined;
  }
  if (targetExcludeSource !== undefined && targetExcludeSource !== 'manual') {
    return undefined;
  }
  if (
    file !== undefined ||
    excludeFile !== undefined ||
    hostsFilter !== undefined
  ) {
    return undefined;
  }
  if (aliveTests !== undefined && !canUseNativeTargetAliveTests(aliveTests)) {
    return undefined;
  }
  if (portListId !== undefined && portListId.length === 0) {
    return undefined;
  }
  const nativeHosts = parseNativeTargetHostList(hosts);
  if (hosts !== undefined && nativeHosts === undefined) {
    return undefined;
  }
  const nativeExcludeHosts = parseNativeTargetHostList(excludeHosts, {
    allowEmpty: true,
  });
  if (excludeHosts !== undefined && nativeExcludeHosts === undefined) {
    return undefined;
  }
  if (excludeHosts !== undefined && nativeHosts === undefined) {
    return undefined;
  }
  const excludedHosts = new Set(nativeExcludeHosts ?? []);
  if (
    nativeHosts !== undefined &&
    nativeHosts.every(host => excludedHosts.has(host))
  ) {
    return undefined;
  }
  const credentials = nativeTargetCredentialsPatchFromParams({
    id,
    name,
    esxiCredentialId,
    krb5CredentialId,
    port,
    smbCredentialId,
    snmpCredentialId,
    sshCredentialId,
    sshElevateCredentialId,
  });
  if (
    credentials === undefined &&
    [
      esxiCredentialId,
      krb5CredentialId,
      smbCredentialId,
      snmpCredentialId,
      sshCredentialId,
      sshElevateCredentialId,
      port,
    ].some(value => value !== undefined)
  ) {
    return undefined;
  }
  return {
    id,
    name,
    comment,
    ...(aliveTests !== undefined ? {aliveTests} : {}),
    ...(allowSimultaneousIPs !== undefined ? {allowSimultaneousIPs} : {}),
    ...(reverseLookupOnly !== undefined ? {reverseLookupOnly} : {}),
    ...(reverseLookupUnify !== undefined ? {reverseLookupUnify} : {}),
    ...(portListId !== undefined ? {portListId} : {}),
    ...(nativeHosts !== undefined ? {hosts: nativeHosts} : {}),
    ...(nativeExcludeHosts !== undefined
      ? {excludeHosts: nativeExcludeHosts}
      : {}),
    ...(credentials !== undefined ? {credentials} : {}),
  };
};

class TargetCommand extends EntityCommand<Target> {
  constructor(http: Http) {
    super(http, 'target', Target);
  }

  async get({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      const nativeResponse = await fetchNativeTarget(this.http, id);
      return new Response(nativeResponse.target);
    }
    return super.get({id});
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeTargetMetadata(this.http, id);
  }

  async clone({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      return await cloneNativeTarget(this.http, id);
    }
    return super.clone({id});
  }

  async delete({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      await deleteNativeTarget(this.http, id);
      return;
    }
    return super.delete({id});
  }

  async create({
    name,
    comment = '',
    targetSource,
    targetExcludeSource,
    hosts,
    excludeHosts,
    reverseLookupOnly,
    reverseLookupUnify,
    portListId,
    aliveTests,
    allowSimultaneousIPs,
    sshCredentialId = UNSET_VALUE,
    sshElevateCredentialId = UNSET_VALUE,
    port,
    smbCredentialId = UNSET_VALUE,
    esxiCredentialId = UNSET_VALUE,
    snmpCredentialId = UNSET_VALUE,
    krb5CredentialId = UNSET_VALUE,
    file,
    excludeFile,
    hostsFilter,
  }: TargetCommandCreateParams) {
    const nativeCreateArgs = nativeTargetCreateArgsFromParams({
      aliveTests,
      allowSimultaneousIPs,
      comment,
      esxiCredentialId,
      excludeFile,
      excludeHosts,
      file,
      hosts,
      hostsFilter,
      krb5CredentialId,
      name,
      port,
      portListId,
      reverseLookupOnly,
      reverseLookupUnify,
      smbCredentialId,
      snmpCredentialId,
      sshCredentialId,
      sshElevateCredentialId,
      targetExcludeSource,
      targetSource,
    });
    if (canUseNativeApi(this.http) && nativeCreateArgs !== undefined) {
      return createNativeTarget(this.http, nativeCreateArgs);
    }

    try {
      return await this.entityAction({
        cmd: 'create_target',
        name,
        comment,
        allow_simultaneous_ips: isDefined(allowSimultaneousIPs)
          ? parseYesNo(allowSimultaneousIPs)
          : undefined,
        target_source: targetSource,
        target_exclude_source: targetExcludeSource,
        hosts,
        exclude_hosts: excludeHosts,
        reverse_lookup_only: isDefined(reverseLookupOnly)
          ? parseYesNo(reverseLookupOnly)
          : undefined,
        reverse_lookup_unify: isDefined(reverseLookupUnify)
          ? parseYesNo(reverseLookupUnify)
          : undefined,
        port_list_id: portListId,
        'alive_tests:': aliveTests,
        port,
        ssh_credential_id: sshCredentialId,
        ssh_elevate_credential_id:
          sshCredentialId === UNSET_VALUE
            ? UNSET_VALUE
            : sshElevateCredentialId,
        smb_credential_id: smbCredentialId,
        esxi_credential_id: esxiCredentialId,
        snmp_credential_id: snmpCredentialId,
        krb5_credential_id: krb5CredentialId,
        file,
        exclude_file: excludeFile,
        hosts_filter: filterString(hostsFilter),
      });
    } catch (rejection) {
      await feedStatusRejection(rejection as Error);
      // never reached because feedStatusRejection always throws. just to satisfy TS
      throw rejection;
    }
  }

  async save(args: TargetCommandSaveArgs) {
    const nativePatchArgs = nativeTargetPatchArgsFromParams(args);
    if (canUseNativeApi(this.http) && nativePatchArgs !== undefined) {
      return patchNativeTarget(this.http, nativePatchArgs);
    }

    const {
      id,
      name,
      comment,
      targetSource,
      targetExcludeSource,
      hosts,
      excludeHosts,
      reverseLookupOnly,
      reverseLookupUnify,
      portListId,
      aliveTests,
      allowSimultaneousIPs,
      sshCredentialId,
      sshElevateCredentialId,
      port,
      smbCredentialId,
      esxiCredentialId,
      snmpCredentialId,
      krb5CredentialId,
      file,
      excludeFile,
    } = args;
    try {
      return await this.action({
        cmd: 'save_target',
        target_id: id,
        'alive_tests:': aliveTests,
        allow_simultaneous_ips: isDefined(allowSimultaneousIPs)
          ? parseYesNo(allowSimultaneousIPs)
          : undefined,
        comment,
        esxi_credential_id: esxiCredentialId,
        exclude_hosts: excludeHosts,
        file,
        exclude_file: excludeFile,
        hosts,
        name,
        port,
        port_list_id: portListId,
        reverse_lookup_only: isDefined(reverseLookupOnly)
          ? parseYesNo(reverseLookupOnly)
          : undefined,
        reverse_lookup_unify: isDefined(reverseLookupUnify)
          ? parseYesNo(reverseLookupUnify)
          : undefined,
        smb_credential_id: smbCredentialId,
        snmp_credential_id: snmpCredentialId,
        ssh_credential_id: sshCredentialId,
        ssh_elevate_credential_id: isDefined(sshCredentialId)
          ? sshElevateCredentialId
          : undefined,
        krb5_credential_id: krb5CredentialId,
        target_source: targetSource,
        target_exclude_source: targetExcludeSource,
      });
    } catch (rejection) {
      await feedStatusRejection(rejection as Error);
      // never reached because feedStatusRejection always throws. just to satisfy TS
      throw rejection;
    }
  }

  getElementFromRoot(root) {
    return root.get_target.get_targets_response.target;
  }
}

export default TargetCommand;

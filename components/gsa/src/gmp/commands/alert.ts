/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand, {type EntityCommandParams} from 'gmp/commands/entity';
import {NATIVE_COMMAND_PAGE_SIZE} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import Alert, {
  type AlertConditionType,
  type AlertEventType,
  type AlertMethodType,
  CONDITION_TYPE_ALWAYS,
  EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
  METHOD_TYPE_EMAIL,
  METHOD_TYPE_SCP,
  METHOD_TYPE_SMB,
  METHOD_TYPE_SNMP,
  METHOD_TYPE_START_TASK,
  METHOD_TYPE_SYSLOG,
} from 'gmp/models/alert';
import type Credential from 'gmp/models/credential';
import type Filter from 'gmp/models/filter';
import type Model from 'gmp/models/model';
import {
  cloneNativeAlert,
  createNativeAlert,
  deleteNativeAlert,
  exportNativeAlertMetadata,
  fetchNativeAlertDefinition,
  patchNativeAlert,
  replaceNativeAlertDefinition,
  testNativeAlert,
  type NativeAlertCreateArgs,
  type NativeAlertDefinitionPutArgs,
} from 'gmp/native-api/alerts';
import {fetchNativeCredentials} from 'gmp/native-api/credentials';
import {fetchNativeFilters} from 'gmp/native-api/filters';
import {fetchNativeReportFormats} from 'gmp/native-api/report-formats';
import {fetchNativeTasks} from 'gmp/native-api/tasks';
import {parseYesNo, YES_VALUE} from 'gmp/parser';

interface AlertCreateParams {
  active: string | number | boolean;
  name: string;
  comment?: string;
  event: AlertEventType;
  condition: AlertConditionType;
  filter_id?: string | number;
  method: AlertMethodType;
  [key: string]: unknown;
}

interface AlertSaveParams extends AlertCreateParams {
  id: string;
  expected_revision: string;
}

interface AlertMetadataSaveParams {
  id: string;
  name: string;
  comment?: string;
}

type AlertSaveArgs = AlertSaveParams | AlertMetadataSaveParams;

interface NewAlertSettings {
  filters: Filter[];
  credentials: Credential[];
  report_formats: Model[];
  tasks: Model[];
}

const nativeAlertSettingsQuery = {
  page: 1,
  pageSize: NATIVE_COMMAND_PAGE_SIZE,
  sort: 'name',
  filter: '',
};

const fetchNativeAlertSettings = async (
  http: Http,
): Promise<NewAlertSettings> => {
  const [reportFormats, credentials, tasks, filters] = await Promise.all([
    fetchNativeReportFormats(http, nativeAlertSettingsQuery),
    fetchNativeCredentials(http, nativeAlertSettingsQuery),
    fetchNativeTasks(http, nativeAlertSettingsQuery),
    fetchNativeFilters(http, nativeAlertSettingsQuery),
  ]);

  return {
    report_formats: reportFormats.reportFormats,
    credentials: credentials.credentials,
    tasks: tasks.tasks,
    filters: filters.filters,
  };
};

const isNativeAlertOptionalId = (value: unknown): boolean =>
  value === 0 || value === '0' || value === undefined;

const isNativeAlertNoFilter = (value: unknown): boolean =>
  value === 0 || value === '0' || value === '' || value === undefined;

const NATIVE_ALERT_METHODS: AlertMethodType[] = [
  METHOD_TYPE_EMAIL,
  METHOD_TYPE_SCP,
  METHOD_TYPE_SMB,
  METHOD_TYPE_SNMP,
  METHOD_TYPE_START_TASK,
  METHOD_TYPE_SYSLOG,
];

const nativeAlertOptionalId = (key: string, value: unknown) =>
  isNativeAlertOptionalId(value) ? {} : {[key]: value};

const nativeAlertString = (value: unknown): string | undefined =>
  typeof value === 'string' ? value : undefined;

const unsupportedNativeAlertDefinition = (reason: string): never => {
  throw new Error(`Unsupported native alert definition: ${reason}`);
};

const retainedNativeAlertDefinition = ({
  active,
  name,
  comment = '',
  event,
  condition,
  filter_id: filterId,
  method,
  ...other
}: AlertCreateParams): NativeAlertDefinitionPutArgs => {
  if (event !== EVENT_TYPE_TASK_RUN_STATUS_CHANGED) {
    return unsupportedNativeAlertDefinition('event');
  }
  if (condition !== CONDITION_TYPE_ALWAYS) {
    return unsupportedNativeAlertDefinition('condition');
  }
  if (!isNativeAlertNoFilter(filterId)) {
    return unsupportedNativeAlertDefinition('filter');
  }
  if (!NATIVE_ALERT_METHODS.includes(method)) {
    return unsupportedNativeAlertDefinition('method');
  }

  const shared = {
    name,
    comment,
    active: parseYesNo(active) === YES_VALUE,
    status: nativeAlertString(other.event_data_status),
  };

  if (method === METHOD_TYPE_SYSLOG) {
    return {method: 'SYSLOG', ...shared};
  }

  if (method === METHOD_TYPE_SNMP) {
    const snmpCommunity = other.method_data_snmp_community;
    const snmpCommunityConfigured =
      other.method_data_snmp_community_configured === '1';
    if (
      (typeof snmpCommunity !== 'string' || snmpCommunity === '') &&
      !snmpCommunityConfigured
    ) {
      return unsupportedNativeAlertDefinition('SNMP community');
    }
    return {
      method: 'SNMP',
      ...shared,
      snmp_agent: other.method_data_snmp_agent,
      snmp_message: other.method_data_snmp_message,
      ...(typeof snmpCommunity === 'string' && snmpCommunity !== ''
        ? {
            snmp_community_mode: 'replace' as const,
            snmp_community: snmpCommunity,
          }
        : {snmp_community_mode: 'preserve' as const}),
    };
  }

  if (method === METHOD_TYPE_START_TASK) {
    return {
      method: 'START_TASK',
      ...shared,
      task_id: other.method_data_start_task_task,
    };
  }

  if (method === METHOD_TYPE_SCP) {
    return {
      method: 'SCP',
      ...shared,
      scp_credential_id: other.method_data_scp_credential,
      scp_host: other.method_data_scp_host,
      scp_port: other.method_data_scp_port,
      scp_known_hosts: other.method_data_scp_known_hosts,
      scp_path: other.method_data_scp_path,
      report_format_id: other.method_data_scp_report_format,
    };
  }

  if (method === METHOD_TYPE_SMB) {
    const smbMaxProtocol = other.method_data_smb_max_protocol;
    return {
      method: 'SMB',
      ...shared,
      smb_credential_id: other.method_data_smb_credential,
      smb_share_path: other.method_data_smb_share_path,
      smb_file_path: other.method_data_smb_file_path,
      report_format_id: other.method_data_smb_report_format,
      ...(smbMaxProtocol === ''
        ? {smb_max_protocol: 'default'}
        : smbMaxProtocol !== undefined
          ? {smb_max_protocol: smbMaxProtocol}
          : {}),
    };
  }

  const email = {
    method: 'EMAIL' as const,
    ...shared,
    to_address: other.method_data_to_address,
    from_address: other.method_data_from_address,
    subject: other.method_data_subject,
    ...nativeAlertOptionalId(
      'recipient_credential_id',
      other.method_data_recipient_credential,
    ),
  };
  switch (other.method_data_notice) {
    case '1':
      return {...email, notice: 'simple'};
    case '0':
      return {
        ...email,
        notice: 'include',
        report_format_id: other.method_data_notice_report_format,
        message: other.method_data_message,
      };
    case '2':
      return {
        ...email,
        notice: 'attach',
        report_format_id: other.method_data_notice_attach_format,
        message: other.method_data_message_attach,
      };
    default:
      return {...email, notice: other.method_data_notice};
  }
};

const nativeAlertCreateRequestFromParams = (
  params: AlertCreateParams,
): NativeAlertCreateArgs => {
  const definition = retainedNativeAlertDefinition(params);
  if (definition.method !== 'SNMP') {
    return definition;
  }

  const {snmp_community_mode: _mode, ...request} = definition;
  return {
    ...request,
    snmp_community: params.method_data_snmp_community,
  };
};

const isAlertMetadataOnlySave = (
  args: AlertSaveArgs,
): args is AlertMetadataSaveParams => {
  const keys = Object.keys(args);
  return (
    keys.every(key => ['id', 'name', 'comment'].includes(key)) &&
    typeof args.id === 'string' &&
    typeof args.name === 'string' &&
    (args.comment === undefined || typeof args.comment === 'string')
  );
};

class AlertCommand extends EntityCommand<Alert> {
  constructor(http: Http) {
    super(http, 'alert', Alert);
  }

  async get({id}: EntityCommandParams) {
    return new Response(await fetchNativeAlertDefinition(this.http, id));
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeAlertMetadata(this.http, id);
  }

  async clone({id}: EntityCommandParams) {
    return await cloneNativeAlert(this.http, id);
  }

  async delete({id}: EntityCommandParams) {
    await deleteNativeAlert(this.http, id);
  }

  create(params: AlertCreateParams) {
    return createNativeAlert(
      this.http,
      nativeAlertCreateRequestFromParams(params),
    );
  }

  async save(args: AlertSaveArgs) {
    if (isAlertMetadataOnlySave(args)) {
      return await patchNativeAlert(this.http, args);
    }

    const {
      id,
      expected_revision: expectedRevision,
      ...params
    } = args as AlertSaveParams;
    return await replaceNativeAlertDefinition(
      this.http,
      id,
      expectedRevision,
      retainedNativeAlertDefinition(params),
    );
  }

  async newAlertSettings() {
    return new Response(await fetchNativeAlertSettings(this.http));
  }

  async editAlertSettings({id}: EntityCommandParams) {
    const [alert, settings] = await Promise.all([
      fetchNativeAlertDefinition(this.http, id),
      fetchNativeAlertSettings(this.http),
    ]);
    return new Response({...settings, alert});
  }

  async test({id}: {id: string}) {
    await testNativeAlert(this.http, id);
  }

  getElementFromRoot(root) {
    return root.get_alert.get_alerts_response.alert;
  }
}

export default AlertCommand;

/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import EntityCommand, {type EntityCommandParams} from 'gmp/commands/entity';
import {canUseNativeApi, NATIVE_COMMAND_PAGE_SIZE} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import logger from 'gmp/log';
import Alert, {
  type AlertConditionType,
  type AlertMethodType,
  type AlertEventType,
  CONDITION_TYPE_ALWAYS,
  EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
  METHOD_TYPE_EMAIL,
  METHOD_TYPE_SCP,
  METHOD_TYPE_SMB,
  METHOD_TYPE_SNMP,
  METHOD_TYPE_SYSLOG,
} from 'gmp/models/alert';
import Credential from 'gmp/models/credential';
import Filter from 'gmp/models/filter';
import {
  type default as Model,
  type ModelElement,
  parseModelFromElement,
} from 'gmp/models/model';
import {
  cloneNativeAlert,
  createNativeAlert,
  deleteNativeAlert,
  exportNativeAlertMetadata,
  fetchNativeAlert,
  patchNativeAlert,
  type NativeAlertCreateArgs,
} from 'gmp/native-api/alerts';
import {fetchNativeCredentials} from 'gmp/native-api/credentials';
import {fetchNativeFilters} from 'gmp/native-api/filters';
import {fetchNativeReportFormats} from 'gmp/native-api/report-formats';
import {fetchNativeTasks} from 'gmp/native-api/tasks';
import {parseYesNo, YES_VALUE} from 'gmp/parser';
import {map} from 'gmp/utils/array';

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
}

interface AlertMetadataSaveParams {
  id: string;
  name: string;
  comment?: string;
}

type AlertSaveArgs = AlertSaveParams | AlertMetadataSaveParams;

interface NewAlertElement {
  new_alert?: {
    get_report_formats_response?: {
      report_format: ModelElement | ModelElement[];
    };
    get_credentials_response?: {
      credential: ModelElement | ModelElement[];
    };
    get_tasks_response?: {
      task: ModelElement | ModelElement[];
    };
    get_filters_response?: {
      filter: ModelElement | ModelElement[];
    };
  };
}

interface EditAlertElement {
  edit_alert?: {
    get_alerts_response?: {
      alert: ModelElement;
    };
    get_report_formats_response?: {
      report_format: ModelElement | ModelElement[];
    };
    get_credentials_response?: {
      credential: ModelElement | ModelElement[];
    };
    get_tasks_response?: {
      task: ModelElement | ModelElement[];
    };
    get_filters_response?: {
      filter: ModelElement | ModelElement[];
    };
  };
}

interface NewAlertSettings {
  filters: Filter[];
  credentials: Credential[];
  report_formats: Model[];
  tasks: Model[];
}

interface EditAlertSettings extends NewAlertSettings {
  alert: Alert;
}

const log = logger.getLogger('gmp.commands.alert');

const ALERT_METADATA_SAVE_KEYS = new Set(['id', 'name', 'comment']);

const isAlertMetadataOnlySave = (
  args: AlertSaveArgs,
): args is AlertMetadataSaveParams => {
  const keys = Object.keys(args);
  return (
    keys.every(key => ALERT_METADATA_SAVE_KEYS.has(key)) &&
    typeof args.id === 'string' &&
    typeof args.name === 'string' &&
    (args.comment === undefined || typeof args.comment === 'string')
  );
};

const event_data_fields = ['status', 'feed_event', 'secinfo_type'];
const method_data_fields = [
  'composer_ignore_pagination',
  'composer_include_overrides',
  'details_url',
  'to_address',
  'from_address',
  'subject',
  'notice',
  'notice_report_format',
  'message',
  'notice_attach_format',
  'message_attach',
  'recipient_credential',
  'submethod', // FIXME remove constant submethod!!!
  'URL',
  'snmp_community',
  'snmp_agent',
  'snmp_message',
  'start_task_task',
  'scp_credential',
  'scp_host',
  'scp_known_hosts',
  'scp_path',
  'scp_port',
  'scp_report_format',
  'smb_credential',
  'smb_file_path',
  'smb_max_protocol',
  'smb_report_format',
  'smb_share_path',
];

const nativeAlertSettingsQuery = {
  page: 1,
  pageSize: NATIVE_COMMAND_PAGE_SIZE,
  sort: 'name',
  filter: '',
};

const fetchNativeAlertSettings = async (
  http: Http,
): Promise<NewAlertSettings> => {
  const [reportFormats, credentials, tasks, filters] =
    await Promise.all([
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

const condition_data_fields = [
  'severity',
  'direction',
  'at_least_filter_id',
  'at_least_count',
  'filter_direction', // FIXME filter_direction is constant
  'filter_id',
  'count',
];

const convertData = (
  prefix: string,
  data: Record<string, unknown>,
  fields: string[],
) => {
  const converted = {};
  for (const field of fields) {
    const name = prefix + '_' + field;
    if (data.hasOwnProperty(name)) {
      converted[prefix + ':' + field] = data[name];
    }
  }
  return converted;
};

const isNativeAlertOptionalId = (value: unknown): boolean =>
  value === 0 || value === '0' || value === undefined;

const isNativeAlertNoFilter = (value: unknown): boolean =>
  value === 0 || value === '0' || value === '' || value === undefined;

const NATIVE_ALERT_CREATE_METHODS: AlertMethodType[] = [
  METHOD_TYPE_EMAIL,
  METHOD_TYPE_SCP,
  METHOD_TYPE_SMB,
  METHOD_TYPE_SNMP,
  METHOD_TYPE_SYSLOG,
];

const nativeAlertOptionalId = (key: string, value: unknown) =>
  isNativeAlertOptionalId(value) ? {} : {[key]: value};

const nativeAlertCreateRequestFromParams = ({
  active,
  name,
  comment = '',
  event,
  condition,
  filter_id: filterId,
  method,
  ...other
}: AlertCreateParams): NativeAlertCreateArgs | undefined => {
  if (
    event !== EVENT_TYPE_TASK_RUN_STATUS_CHANGED ||
    condition !== CONDITION_TYPE_ALWAYS ||
    !isNativeAlertNoFilter(filterId) ||
    !NATIVE_ALERT_CREATE_METHODS.includes(method)
  ) {
    return undefined;
  }

  const shared = {
    name,
    comment,
    active: parseYesNo(active) === YES_VALUE,
    status: other.event_data_status,
  };

  if (method === METHOD_TYPE_SYSLOG) {
    return {method: 'SYSLOG', ...shared};
  }

  if (method === METHOD_TYPE_SNMP) {
    return {
      method: 'SNMP',
      ...shared,
      snmp_agent: other.method_data_snmp_agent,
      snmp_community: other.method_data_snmp_community,
      snmp_message: other.method_data_snmp_message,
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

class AlertCommand extends EntityCommand<Alert> {
  constructor(http: Http) {
    super(http, 'alert', Alert);
  }

  async get({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      return new Response(await fetchNativeAlert(this.http, id));
    }
    return super.get({id});
  }

  async export({id}: EntityCommandParams) {
    return await exportNativeAlertMetadata(this.http, id);
  }

  async clone({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      return await cloneNativeAlert(this.http, id);
    }
    return super.clone({id});
  }

  async delete({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      await deleteNativeAlert(this.http, id);
      return;
    }
    return super.delete({id});
  }

  create({
    active,
    name,
    comment = '',
    event,
    condition,
    filter_id: filterId,
    method,
    ...other
  }: AlertCreateParams) {
    const nativeRequest = nativeAlertCreateRequestFromParams({
      active,
      name,
      comment,
      event,
      condition,
      filter_id: filterId,
      method,
      ...other,
    });
    if (canUseNativeApi(this.http) && nativeRequest !== undefined) {
      return createNativeAlert(this.http, nativeRequest);
    }

    const data = {
      ...convertData('method_data', other, method_data_fields),
      ...convertData('condition_data', other, condition_data_fields),
      ...convertData('event_data', other, event_data_fields),
      cmd: 'create_alert',
      active: parseYesNo(active),
      name,
      comment,
      event,
      condition,
      method,
      filter_id: filterId as string | undefined,
    };
    log.debug('Creating new alert', data);
    return this.action(data);
  }

  save(args: AlertSaveArgs) {
    if (canUseNativeApi(this.http) && isAlertMetadataOnlySave(args)) {
      return patchNativeAlert(this.http, {
        id: args.id,
        name: args.name,
        comment: args.comment,
      });
    }

    const {
      active,
      id,
      name,
      comment = '',
      event,
      condition,
      filter_id,
      method,
      ...other
    } = args as AlertSaveParams;
    const data = {
      ...convertData('method_data', other, method_data_fields),
      ...convertData('condition_data', other, condition_data_fields),
      ...convertData('event_data', other, event_data_fields),
      cmd: 'save_alert',
      id,
      active: parseYesNo(active),
      name,
      comment,
      event,
      condition,
      method,
      filter_id: filter_id as string | undefined,
    };
    log.debug('Saving alert', data);
    return this.action(data);
  }

  async newAlertSettings() {
    if (canUseNativeApi(this.http)) {
      return new Response(await fetchNativeAlertSettings(this.http));
    }

    // newAlertSettings should be removed after all corresponding gmp commands are implemented
    // and UI queries are adapted to use them directly
    const response = (await this.httpGetWithTransform({
      cmd: 'new_alert',
    })) as Response<NewAlertElement>;
    const {new_alert} = response.data;
    const newAlert: NewAlertSettings = {
      report_formats: map(
        new_alert?.get_report_formats_response?.report_format,
        format => parseModelFromElement(format, 'reportformat'),
      ),
      credentials: map(
        new_alert?.get_credentials_response?.credential,
        credential => Credential.fromElement(credential),
      ),
      // don't use Task here to avoid cyclic dependencies
      tasks: map(new_alert?.get_tasks_response?.task, task =>
        parseModelFromElement(task, 'task'),
      ),
      filters: map(new_alert?.get_filters_response?.filter, filter =>
        Filter.fromElement(filter),
      ),
    };

    return response.setData(newAlert);
  }

  async editAlertSettings({id}: EntityCommandParams) {
    if (canUseNativeApi(this.http)) {
      const [alert, settings] = await Promise.all([
        fetchNativeAlert(this.http, id),
        fetchNativeAlertSettings(this.http),
      ]);
      return new Response({
        ...settings,
        alert,
      });
    }

    const response = (await this.httpGetWithTransform({
      cmd: 'edit_alert',
      id,
    })) as Response<EditAlertElement>;
    const {edit_alert} = response.data;
    const editAlert: EditAlertSettings = {
      alert: Alert.fromElement(edit_alert?.get_alerts_response?.alert),
      report_formats: map(
        edit_alert?.get_report_formats_response?.report_format,
        format => parseModelFromElement(format, 'reportformat'),
      ),
      credentials: map(
        edit_alert?.get_credentials_response?.credential,
        credential => Credential.fromElement(credential),
      ),
      tasks: map(edit_alert?.get_tasks_response?.task, task =>
        parseModelFromElement(task, 'task'),
      ), // don't use Task here to avoid cyclic dependencies
      filters: map(edit_alert?.get_filters_response?.filter, filter =>
        Filter.fromElement(filter),
      ),
    };
    return response.setData(editAlert);
  }

  test({id}: {id: string}) {
    return this.httpPostWithTransform({
      cmd: 'test_alert',
      id,
    });
  }

  getElementFromRoot(root) {
    return root.get_alert.get_alerts_response.alert;
  }
}

export default AlertCommand;

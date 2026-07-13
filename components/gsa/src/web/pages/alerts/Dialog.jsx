/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import styled from 'styled-components';
import _ from 'gmp/locale';
import {
  CONDITION_TYPE_ALWAYS,
  EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
  METHOD_TYPE_ALEMBA_VFIRE,
  METHOD_TYPE_SCP,
  METHOD_TYPE_SMB,
  METHOD_TYPE_SNMP,
  METHOD_TYPE_SYSLOG,
  METHOD_TYPE_EMAIL,
  METHOD_TYPE_START_TASK,
  METHOD_TYPE_HTTP_GET,
  METHOD_TYPE_VERINICE,
  METHOD_TYPE_TIPPING_POINT,
  isTaskEvent,
  isSecinfoEvent,
} from 'gmp/models/alert';
import {NO_VALUE, YES_VALUE} from 'gmp/parser';
import {selectSaveId} from 'gmp/utils/id';
import {isDefined} from 'gmp/utils/identity';
import SaveDialog from 'web/components/dialog/SaveDialog';
import FormGroup from 'web/components/form/FormGroup';
import Radio from 'web/components/form/Radio';
import Select from 'web/components/form/Select';
import TextField from 'web/components/form/TextField';
import YesNoRadio from 'web/components/form/YesNoRadio';
import {ReportIcon} from 'web/components/icon';
import Divider from 'web/components/layout/Divider';
import AlembaVfireMethodPart from 'web/pages/alerts/dialog/AlembavFireMethodPart';
import EmailMethodPart from 'web/pages/alerts/dialog/EmailMethodPart';
import HttpMethodPart from 'web/pages/alerts/dialog/HttpMethodPart';
import ScpMethodPart from 'web/pages/alerts/dialog/ScpMethodPart';
import SmbMethodPart from 'web/pages/alerts/dialog/SmbMethodPart';
import SnmpMethodPart from 'web/pages/alerts/dialog/SnmpMethodPart';
import StartTaskMethodPart from 'web/pages/alerts/dialog/StartTaskMethodPart';
import TippingPontMethodPart from 'web/pages/alerts/dialog/TippingPointMethodPart';
import VeriniceMethodPart from 'web/pages/alerts/dialog/VeriniceMethodPart';
import FilterCountChangedConditionPart from 'web/pages/alerts/FilterCountChangedConditionPart';
import FilterCountLeastConditionPart from 'web/pages/alerts/FilterCountLeastConditionPart';
import SecInfoEventPart from 'web/pages/alerts/SecInfoEventPart';
import SeverityChangedConditionPart from 'web/pages/alerts/SeverityChangedConditionPart';
import SeverityLeastConditionPart from 'web/pages/alerts/SeverityLeastConditionPart';
import TaskEventPart from 'web/pages/alerts/TaskEventPart';
import PropTypes from 'web/utils/PropTypes';
import {UNSET_VALUE} from 'web/utils/Render';
import withCapabilities from 'web/utils/withCapabilities';

export const DEFAULT_DIRECTION = 'changed';
export const DEFAULT_EVENT_STATUS = 'Done';
export const DEFAULT_METHOD = METHOD_TYPE_EMAIL;
export const DEFAULT_SCP_PATH = 'report.xml';
export const DEFAULT_SECINFO_TYPE = 'nvt';
export const DEFAULT_SEVERITY = 0.1;

export const DEFAULT_DETAILS_URL =
  'https://secinfo.greenbone.net/omp?' +
  'cmd=get_info&info_type=$t&info_id=$o&details=1&token=guest';

export const DEFAULT_NOTICE = '1';
export const NOTICE_SIMPLE = '1';
export const NOTICE_INCLUDE = '0';
export const NOTICE_ATTACH = '2';

export const DEFAULT_NOTICE_REPORT_FORMAT =
  'a3810a62-1f62-11e1-9219-406186ea4fc5';
export const DEFAULT_NOTICE_REPORT_CONFIG = UNSET_VALUE;
export const DEFAULT_NOTICE_ATTACH_FORMAT =
  'a0b5bfb2-1f62-11e1-85db-406186ea4fc5';

export const TASK_SUBJECT = "[GVM] Task '$n': $e";
export const SECINFO_SUBJECT = '[GVM] $T $q $S since $d';

export const INCLUDE_MESSAGE_DEFAULT = `Task '$n': $e'

After the event $e,
the following condition was met: $c

This email escalation is configured to apply report format '$r'.
Full details and other report formats are available on the scan engine.

$t
$i

Note:
This email was sent to you as a configured security scan escalation.
Please contact your local system administrator if you think you
should not have received it.`;

export const INCLUDE_MESSAGE_SECINFO = `After the event $e,
the following condition was met: $c

$t
$i

Note:
This email was sent to you as a configured security information escalation.
Please contact your local system administrator if you think you
should not have received it.`;

export const ATTACH_MESSAGE_DEFAULT = `Task '$n': $e

After the event $e,
the following condition was met: $c

This email escalation is configured to attach report format '$r'.
Full details and other report formats are available on the scan engine.

$t

Note:
This email was sent to you as a configured security scan escalation.
Please contact your local system administrator if you think you
should not have received it.`;

export const ATTACH_MESSAGE_SECINFO = `After the event $e,
the following condition was met: $c

This email escalation is configured to attach the resource list.

$t

Note:
This email was sent to you as a configured security information escalation.
Please contact your local system administrator if you think you
should not have received it.
`;

export const VFIRE_CALL_DESCRIPTION = `After the event $e,
the following condition was met: $c

This alert includes reports in the following format(s):
$r.

Full details and other report formats are available on the scan engine.
$t

Note:
This alert was created automatically as a security scan escalation.
Please contact your local system administrator if you think it
was created erroneously.
`;

const DEFAULTS = {
  active: YES_VALUE,
  comment: '',
  condition: CONDITION_TYPE_ALWAYS,
  condition_data_at_least_count: 1,
  condition_data_count: 1,
  condition_data_direction: DEFAULT_DIRECTION,
  condition_data_filters: [],
  condition_data_severity: DEFAULT_SEVERITY,
  event_data_feed_event: 'new',
  event_data_secinfo_type: DEFAULT_SECINFO_TYPE,
  event_data_status: DEFAULT_EVENT_STATUS,
  event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
  filter_id: 0,
  filters: [],
  method: DEFAULT_METHOD,
  method_data_details_url: DEFAULT_DETAILS_URL,
  method_data_from_address: '',
  method_data_message_attach: ATTACH_MESSAGE_DEFAULT,
  method_data_message: INCLUDE_MESSAGE_DEFAULT,
  method_data_notice: DEFAULT_NOTICE,
  method_data_notice_attach_format: DEFAULT_NOTICE_ATTACH_FORMAT,
  method_data_notice_report_format: DEFAULT_NOTICE_REPORT_FORMAT,
  method_data_notice_attach_config: DEFAULT_NOTICE_REPORT_CONFIG,
  method_data_notice_report_config: DEFAULT_NOTICE_REPORT_CONFIG,
  method_data_scp_path: DEFAULT_SCP_PATH,
  method_data_scp_host: '',
  method_data_scp_port: 22,
  method_data_scp_known_hosts: '',
  method_data_smb_file_path: 'report.xml',
  method_data_smb_share_path: '\\\\localhost\\gvm-reports',
  method_data_snmp_agent: 'localhost',
  method_data_snmp_community: 'public',
  method_data_snmp_message: '$e',
  method_data_status: 'Done',
  method_data_subject: TASK_SUBJECT,
  method_data_submethod: 'syslog',
  method_data_to_address: '',
  method_data_tp_sms_hostname: '',
  method_data_tp_sms_tls_workaround: NO_VALUE,
  method_data_URL: '',
  name: _('Unnamed'),
  report_configs: [],
  report_config_ids: [],
  report_formats: [],
  report_format_ids: [],
  result_filters: [],
  secinfo_filters: [],
};

const StyledDivider = styled(Divider)`
  cursor: pointer;
`;

class AlertDialog extends React.Component {
  constructor(...args) {
    super(...args);

    const {event} = this.props;

    this.state = {
      stateEvent: isDefined(event) ? event : EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
    };

    this.handleEventChange = this.handleEventChange.bind(this);
  }

  handleEventChange(value, onValueChange) {
    const {result_filters, secinfo_filters} = this.props;

    const is_task_event = isTaskEvent(value);
    let filter_id;

    if (onValueChange) {
      onValueChange(CONDITION_TYPE_ALWAYS, 'condition'); // reset condition

      if (is_task_event) {
        onValueChange(TASK_SUBJECT, 'method_data_subject');
        onValueChange(INCLUDE_MESSAGE_DEFAULT, 'method_data_message');
        onValueChange(ATTACH_MESSAGE_DEFAULT, 'method_data_message_attach');
        onValueChange(result_filters, 'condition_data_filters');
        filter_id = selectSaveId(result_filters);
      } else {
        onValueChange(DEFAULT_METHOD, 'method'); // reset method to avoid having an invalid method for secinfo
        onValueChange(SECINFO_SUBJECT, 'method_data_subject');
        onValueChange(INCLUDE_MESSAGE_SECINFO, 'method_data_message');
        onValueChange(ATTACH_MESSAGE_SECINFO, 'method_data_message_attach');
        onValueChange(secinfo_filters, 'condition_data_filters');

        filter_id = selectSaveId(secinfo_filters);
        onValueChange(UNSET_VALUE, 'filter_id'); // reset filter_id
      }

      onValueChange(filter_id, 'condition_data_at_least_filter_id');
    }
    // in addition to changing the event in the dialog, change it here as well
    // to have it handy in render()
    this.setState({stateEvent: value});
  }

  render() {
    const {
      capabilities,
      credentials,
      filter_id,
      title = _('New Alert'),
      report_config_ids,
      report_configs,
      report_format_ids,
      report_formats,
      method_data_composer_ignore_pagination,
      method_data_composer_include_overrides,
      method_data_recipient_credential,
      method_data_scp_credential,
      method_data_smb_credential,
      method_data_tp_sms_credential,
      method_data_verinice_server_credential,
      method_data_vfire_base_url,
      method_data_vfire_credential,
      method_data_vfire_session_type,
      method_data_vfire_client_id,
      method_data_vfire_call_partition_name,
      method_data_vfire_call_description,
      method_data_vfire_call_template_name,
      method_data_vfire_call_type_name,
      method_data_vfire_call_impact_name,
      method_data_vfire_call_urgency_name,
      onClose,
      onEmailCredentialChange,
      onNewEmailCredentialClick,
      onNewScpCredentialClick,
      onNewSmbCredentialClick,
      onNewVeriniceCredentialClick,
      onNewVfireCredentialClick,
      onNewTippingPointCredentialClick,
      onOpenContentComposerDialogClick,
      onReportConfigsChange,
      onReportFormatsChange,
      onSave,
      onScpCredentialChange,
      onSmbCredentialChange,
      onTippingPointCredentialChange,
      onVerinceCredentialChange,
      onVfireCredentialChange,
      ...props
    } = this.props;

    const {stateEvent: event} = this.state;

    const methodTypes = [];

    const taskEvent = isTaskEvent(event);
    const secinfoEvent = isSecinfoEvent(event);

    if (taskEvent) {
      methodTypes.push(
        {
          value: METHOD_TYPE_EMAIL,
          label: _('Email'),
        },
        {
          value: METHOD_TYPE_HTTP_GET,
          label: _('HTTP Get'),
        },
        {
          value: METHOD_TYPE_SCP,
          label: _('SCP'),
        },
        {
          value: METHOD_TYPE_SMB,
          label: _('SMB'),
        },
        {
          value: METHOD_TYPE_SNMP,
          label: _('SNMP'),
        },
        {
          value: METHOD_TYPE_START_TASK,
          label: _('Start Task'),
        },
        {
          value: METHOD_TYPE_SYSLOG,
          label: _('System Logger'),
        },
        {
          value: METHOD_TYPE_VERINICE,
          label: _('verinice.PRO Connector'),
        },
        {
          value: METHOD_TYPE_TIPPING_POINT,
          label: _('TippingPoint SMS'),
        },
        {
          value: METHOD_TYPE_ALEMBA_VFIRE,
          label: _('Alemba vFire'),
        },
      );
    } else {
      methodTypes.push(
        {
          value: METHOD_TYPE_EMAIL,
          label: _('Email'),
        },
        {
          value: METHOD_TYPE_SCP,
          label: _('SCP'),
        },
        {
          value: METHOD_TYPE_SMB,
          label: _('SMB'),
        },
        {
          value: METHOD_TYPE_SNMP,
          label: _('SNMP'),
        },
        {
          value: METHOD_TYPE_START_TASK,
          label: _('Start Task'),
        },
        {
          value: METHOD_TYPE_SYSLOG,
          label: _('System Logger'),
        },
        {
          value: METHOD_TYPE_VERINICE,
          label: _('verinice.PRO Connector'),
        },
        {
          value: METHOD_TYPE_TIPPING_POINT,
          label: _('TippingPoint SMS'),
        },
        {
          value: METHOD_TYPE_ALEMBA_VFIRE,
          label: _('Alemba vFire'),
        },
      );
    }

    const data = {
      ...DEFAULTS,
      ...alert,
      method_data_vfire_base_url,
      method_data_vfire_client_id,
      method_data_vfire_call_partition_name,
      method_data_vfire_call_description,
      method_data_vfire_call_template_name,
      method_data_vfire_call_type_name,
      method_data_vfire_call_impact_name,
      method_data_vfire_call_urgency_name,
      method_data_vfire_session_type,
    };

    for (const [key, value] of Object.entries(props)) {
      if (isDefined(value)) {
        data[key] = value;
      }
    }

    const controlledValues = {
      event,
      filter_id,
      method_data_composer_ignore_pagination,
      method_data_composer_include_overrides,
      method_data_recipient_credential,
      method_data_scp_credential,
      method_data_smb_credential,
      method_data_tp_sms_credential,
      method_data_verinice_server_credential,
      method_data_vfire_credential,
      report_config_ids,
      report_format_ids,
    };

    return (
      <SaveDialog
        defaultValues={data}
        title={title}
        values={controlledValues}
        onClose={onClose}
        onSave={onSave}
      >
        {({values, onValueChange}) => {
          return (
            <>
              <FormGroup title={_('Name')}>
                <TextField
                  grow="1"
                  name="name"
                  value={values.name}
                  onChange={onValueChange}
                />
              </FormGroup>

              <FormGroup title={_('Comment')}>
                <TextField
                  grow="1"
                  name="comment"
                  value={values.comment}
                  onChange={onValueChange}
                />
              </FormGroup>

              <FormGroup title={_('Event')}>
                <TaskEventPart
                  event={values.event}
                  prefix="event_data"
                  status={values.event_data_status}
                  onChange={onValueChange}
                  onEventChange={value =>
                    this.handleEventChange(value, onValueChange)
                  }
                />

                <SecInfoEventPart
                  event={values.event}
                  feedEvent={values.event_data_feed_event}
                  prefix="event_data"
                  secinfoType={values.event_data_secinfo_type}
                  onChange={onValueChange}
                  onEventChange={value =>
                    this.handleEventChange(value, onValueChange)
                  }
                />
              </FormGroup>

              <FormGroup title={_('Condition')}>
                <Radio
                  checked={values.condition === CONDITION_TYPE_ALWAYS}
                  name="condition"
                  title={_('Always')}
                  value={CONDITION_TYPE_ALWAYS}
                  onChange={onValueChange}
                />

                {taskEvent && (
                  <SeverityLeastConditionPart
                    condition={values.condition}
                    prefix="condition_data"
                    severity={values.condition_data_severity}
                    onChange={onValueChange}
                  />
                )}

                {taskEvent && (
                  <SeverityChangedConditionPart
                    condition={values.condition}
                    direction={values.condition_data_direction}
                    prefix="condition_data"
                    onChange={onValueChange}
                  />
                )}

                {(secinfoEvent || taskEvent) && (
                  <FilterCountLeastConditionPart
                    atLeastCount={values.condition_data_at_least_count}
                    atLeastFilterId={values.condition_data_at_least_filter_id}
                    condition={values.condition}
                    filters={values.condition_data_filters}
                    prefix="condition_data"
                    onChange={onValueChange}
                  />
                )}

                {taskEvent && (
                  <FilterCountChangedConditionPart
                    condition={values.condition}
                    count={values.condition_data_count}
                    filterId={values.condition_data_filter_id}
                    filters={values.condition_data_filters}
                    prefix="condition_data"
                    onChange={onValueChange}
                  />
                )}
              </FormGroup>

              {secinfoEvent && (
                <FormGroup title={_('Details URL')}>
                  <TextField
                    grow="1"
                    name="method_data_details_url"
                    value={values.method_data_details_url}
                    onChange={onValueChange}
                  />
                </FormGroup>
              )}

              {capabilities.mayOp('get_filters') && taskEvent && (
                <FormGroup title={_('Report Content')}>
                  <StyledDivider onClick={onOpenContentComposerDialogClick}>
                    <ReportIcon title={_('Compose Report Content')} />
                    <span>{_('Compose')}</span>
                  </StyledDivider>
                </FormGroup>
              )}

              <FormGroup title={_('Method')}>
                <Select
                  items={methodTypes}
                  name="method"
                  value={values.method}
                  onChange={onValueChange}
                />
              </FormGroup>

              {values.method === METHOD_TYPE_EMAIL && (
                <EmailMethodPart
                  credentials={credentials}
                  event={event}
                  fromAddress={values.method_data_from_address}
                  message={values.method_data_message}
                  messageAttach={values.method_data_message_attach}
                  notice={values.method_data_notice}
                  noticeAttachConfig={values.method_data_notice_attach_config}
                  noticeAttachFormat={values.method_data_notice_attach_format}
                  noticeReportConfig={values.method_data_notice_report_config}
                  noticeReportFormat={values.method_data_notice_report_format}
                  prefix="method_data"
                  recipientCredential={values.method_data_recipient_credential}
                  reportConfigs={report_configs}
                  reportFormats={report_formats}
                  subject={values.method_data_subject}
                  toAddress={values.method_data_to_address}
                  onChange={onValueChange}
                  onCredentialChange={onEmailCredentialChange}
                  onNewCredentialClick={onNewEmailCredentialClick}
                  onSave={onSave}
                />
              )}

              {values.method === METHOD_TYPE_HTTP_GET && (
                <HttpMethodPart
                  URL={values.method_data_URL}
                  prefix="method_data"
                  onChange={onValueChange}
                />
              )}

              {values.method === METHOD_TYPE_SCP && (
                <ScpMethodPart
                  credentials={credentials}
                  prefix="method_data"
                  reportConfigs={report_configs}
                  reportFormats={report_formats}
                  scpCredential={values.method_data_scp_credential}
                  scpHost={values.method_data_scp_host}
                  scpKnownHosts={values.method_data_scp_known_hosts}
                  scpPath={values.method_data_scp_path}
                  scpPort={values.method_data_scp_port}
                  scpReportConfig={values.method_data_scp_report_config}
                  scpReportFormat={values.method_data_scp_report_format}
                  onChange={onValueChange}
                  onCredentialChange={onScpCredentialChange}
                  onNewCredentialClick={onNewScpCredentialClick}
                />
              )}

              {values.method === METHOD_TYPE_START_TASK && (
                <StartTaskMethodPart
                  prefix="method_data"
                  startTaskTask={values.method_data_start_task_task}
                  tasks={values.tasks}
                  onChange={onValueChange}
                />
              )}

              {values.method === METHOD_TYPE_SMB && (
                <SmbMethodPart
                  credentials={credentials}
                  prefix="method_data"
                  reportConfigs={report_configs}
                  reportFormats={report_formats}
                  smbCredential={values.method_data_smb_credential}
                  smbFilePath={values.method_data_smb_file_path}
                  smbMaxProtocol={values.method_data_smb_max_protocol}
                  smbReportConfig={values.method_data_smb_report_config}
                  smbReportFormat={values.method_data_smb_report_format}
                  smbSharePath={values.method_data_smb_share_path}
                  onChange={onValueChange}
                  onCredentialChange={onSmbCredentialChange}
                  onNewCredentialClick={onNewSmbCredentialClick}
                />
              )}

              {values.method === METHOD_TYPE_SNMP && (
                <SnmpMethodPart
                  prefix="method_data"
                  snmpAgent={values.method_data_snmp_agent}
                  snmpCommunity={values.method_data_snmp_community}
                  snmpMessage={values.method_data_snmp_message}
                  onChange={onValueChange}
                />
              )}

              {values.method === METHOD_TYPE_VERINICE && (
                <VeriniceMethodPart
                  credentials={credentials}
                  prefix="method_data"
                  reportConfigs={report_configs}
                  reportFormats={report_formats}
                  veriniceServerCredential={
                    values.method_data_verinice_server_credential
                  }
                  veriniceServerReportConfig={
                    values.method_data_verinice_server_report_config
                  }
                  veriniceServerReportFormat={
                    values.method_data_verinice_server_report_format
                  }
                  veriniceServerUrl={values.method_data_verinice_server_url}
                  onChange={onValueChange}
                  onCredentialChange={onVerinceCredentialChange}
                  onNewCredentialClick={onNewVeriniceCredentialClick}
                />
              )}

              {values.method === METHOD_TYPE_TIPPING_POINT && (
                <TippingPontMethodPart
                  credentials={credentials}
                  prefix="method_data"
                  tpSmsCredential={values.method_data_tp_sms_credential}
                  tpSmsHostname={values.method_data_tp_sms_hostname}
                  tpSmsTlsCertificate={
                    values.method_data_tp_sms_tls_certificate
                  }
                  tpSmsTlsWorkaround={values.method_data_tp_sms_tls_workaround}
                  onChange={onValueChange}
                  onCredentialChange={onTippingPointCredentialChange}
                  onNewCredentialClick={onNewTippingPointCredentialClick}
                />
              )}

              {values.method === METHOD_TYPE_ALEMBA_VFIRE && (
                <AlembaVfireMethodPart
                  credentials={credentials}
                  prefix="method_data"
                  reportFormatIds={values.report_format_ids}
                  reportFormats={report_formats}
                  vFireBaseUrl={values.method_data_vfire_base_url}
                  vFireCallDescription={
                    values.method_data_vfire_call_description
                  }
                  vFireCallImpactName={
                    values.method_data_vfire_call_impact_name
                  }
                  vFireCallPartitionName={
                    values.method_data_vfire_call_partition_name
                  }
                  vFireCallTemplateName={
                    values.method_data_vfire_call_template_name
                  }
                  vFireCallTypeName={values.method_data_vfire_call_type_name}
                  vFireCallUrgencyName={
                    values.method_data_vfire_call_urgency_name
                  }
                  vFireClientId={values.method_data_vfire_client_id}
                  vFireCredential={values.method_data_vfire_credential}
                  vFireSessionType={values.method_data_vfire_session_type}
                  onChange={onValueChange}
                  onCredentialChange={onVfireCredentialChange}
                  onNewVfireCredentialClick={onNewVfireCredentialClick}
                  onReportConfigsChange={onReportConfigsChange}
                  onReportFormatsChange={onReportFormatsChange}
                />
              )}

              <FormGroup title={_('Active')}>
                <YesNoRadio
                  name="active"
                  value={values.active}
                  onChange={onValueChange}
                />
              </FormGroup>
            </>
          );
        }}
      </SaveDialog>
    );
  }
}

AlertDialog.propTypes = {
  active: PropTypes.yesno,
  capabilities: PropTypes.capabilities.isRequired,
  comment: PropTypes.string,
  condition: PropTypes.string,
  condition_data_at_least_count: PropTypes.number,
  condition_data_at_least_filter_id: PropTypes.id,
  condition_data_count: PropTypes.number,
  condition_data_direction: PropTypes.string,
  condition_data_filter_id: PropTypes.id,
  condition_data_filters: PropTypes.array,
  condition_data_severity: PropTypes.number,
  credentials: PropTypes.array,
  event: PropTypes.string,
  event_data_feed_event: PropTypes.string,
  event_data_secinfo_type: PropTypes.string,
  event_data_status: PropTypes.string,
  filter_id: PropTypes.idOrZero,
  method: PropTypes.string,
  method_data_URL: PropTypes.string,
  method_data_composer_ignore_pagination: PropTypes.number,
  method_data_composer_include_overrides: PropTypes.number,
  method_data_details_url: PropTypes.string,
  method_data_from_address: PropTypes.string,
  method_data_message: PropTypes.string,
  method_data_message_attach: PropTypes.string,
  method_data_notice: PropTypes.string,
  method_data_notice_attach_config: PropTypes.id,
  method_data_notice_attach_format: PropTypes.id,
  method_data_notice_report_config: PropTypes.id,
  method_data_notice_report_format: PropTypes.id,
  method_data_recipient_credential: PropTypes.id,
  method_data_scp_credential: PropTypes.id,
  method_data_scp_host: PropTypes.string,
  method_data_scp_known_hosts: PropTypes.string,
  method_data_scp_path: PropTypes.string,
  method_data_scp_port: PropTypes.number,
  method_data_scp_report_config: PropTypes.id,
  method_data_scp_report_format: PropTypes.id,
  method_data_smb_credential: PropTypes.id,
  method_data_smb_file_path: PropTypes.string,
  method_data_smb_report_config: PropTypes.id,
  method_data_smb_report_format: PropTypes.id,
  method_data_smb_share_path: PropTypes.string,
  method_data_snmp_agent: PropTypes.string,
  method_data_snmp_community: PropTypes.string,
  method_data_snmp_message: PropTypes.string,
  method_data_start_task_task: PropTypes.id,
  method_data_subject: PropTypes.string,
  method_data_to_address: PropTypes.string,
  method_data_tp_sms_credential: PropTypes.id,
  method_data_tp_sms_hostname: PropTypes.string,
  method_data_tp_sms_tls_workaround: PropTypes.yesno,
  method_data_verinice_server_credential: PropTypes.id,
  method_data_verinice_server_report_config: PropTypes.id,
  method_data_verinice_server_report_format: PropTypes.id,
  method_data_verinice_server_url: PropTypes.string,
  method_data_vfire_base_url: PropTypes.string,
  method_data_vfire_call_description: PropTypes.string,
  method_data_vfire_call_impact_name: PropTypes.string,
  method_data_vfire_call_partition_name: PropTypes.string,
  method_data_vfire_call_template_name: PropTypes.string,
  method_data_vfire_call_type_name: PropTypes.string,
  method_data_vfire_call_urgency_name: PropTypes.string,
  method_data_vfire_client_id: PropTypes.string,
  method_data_vfire_credential: PropTypes.id,
  method_data_vfire_session_type: PropTypes.string,
  name: PropTypes.string,
  report_config_ids: PropTypes.array,
  report_configs: PropTypes.array,
  report_format_ids: PropTypes.array,
  report_formats: PropTypes.array,
  result_filters: PropTypes.array,
  secinfo_filters: PropTypes.array,
  tasks: PropTypes.array,
  title: PropTypes.string,
  onClose: PropTypes.func.isRequired,
  onEmailCredentialChange: PropTypes.func.isRequired,
  onNewEmailCredentialClick: PropTypes.func.isRequired,
  onNewScpCredentialClick: PropTypes.func.isRequired,
  onNewSmbCredentialClick: PropTypes.func.isRequired,
  onNewTippingPointCredentialClick: PropTypes.func.isRequired,
  onNewVeriniceCredentialClick: PropTypes.func.isRequired,
  onNewVfireCredentialClick: PropTypes.func.isRequired,
  onOpenContentComposerDialogClick: PropTypes.func.isRequired,
  onReportConfigsChange: PropTypes.func.isRequired,
  onReportFormatsChange: PropTypes.func.isRequired,
  onSave: PropTypes.func.isRequired,
  onScpCredentialChange: PropTypes.func.isRequired,
  onSmbCredentialChange: PropTypes.func.isRequired,
  onTippingPointCredentialChange: PropTypes.func.isRequired,
  onVerinceCredentialChange: PropTypes.func.isRequired,
  onVfireCredentialChange: PropTypes.func.isRequired,
};

export default withCapabilities(AlertDialog);

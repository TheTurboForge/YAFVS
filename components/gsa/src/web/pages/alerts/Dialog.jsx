/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import _ from 'gmp/locale';
import {
  CONDITION_TYPE_ALWAYS,
  EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
  METHOD_TYPE_SCP,
  METHOD_TYPE_SMB,
  METHOD_TYPE_SNMP,
  METHOD_TYPE_SYSLOG,
  METHOD_TYPE_EMAIL,
  METHOD_TYPE_START_TASK,
} from 'gmp/models/alert';
import {YES_VALUE} from 'gmp/parser';
import {isDefined} from 'gmp/utils/identity';
import SaveDialog from 'web/components/dialog/SaveDialog';
import FormGroup from 'web/components/form/FormGroup';
import Radio from 'web/components/form/Radio';
import Select from 'web/components/form/Select';
import TextField from 'web/components/form/TextField';
import YesNoRadio from 'web/components/form/YesNoRadio';
import EmailMethodPart from 'web/pages/alerts/dialog/EmailMethodPart';
import ScpMethodPart from 'web/pages/alerts/dialog/ScpMethodPart';
import SmbMethodPart from 'web/pages/alerts/dialog/SmbMethodPart';
import SnmpMethodPart from 'web/pages/alerts/dialog/SnmpMethodPart';
import StartTaskMethodPart from 'web/pages/alerts/dialog/StartTaskMethodPart';
import TaskEventPart from 'web/pages/alerts/TaskEventPart';
import PropTypes from 'web/utils/PropTypes';

export const DEFAULT_DIRECTION = 'changed';
export const DEFAULT_EVENT_STATUS = 'Done';
export const DEFAULT_METHOD = METHOD_TYPE_EMAIL;
export const DEFAULT_SCP_PATH = 'report.xml';
export const DEFAULT_SECINFO_TYPE = 'nvt';
export const DEFAULT_SEVERITY = 0.1;

export const DEFAULT_NOTICE = '1';
export const NOTICE_SIMPLE = '1';
export const NOTICE_INCLUDE = '0';
export const NOTICE_ATTACH = '2';

export const DEFAULT_NOTICE_REPORT_FORMAT =
  'a3810a62-1f62-11e1-9219-406186ea4fc5';
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

const DEFAULTS = {
  active: YES_VALUE,
  comment: '',
  condition: CONDITION_TYPE_ALWAYS,
  event_data_status: DEFAULT_EVENT_STATUS,
  event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
  filter_id: 0,
  method: DEFAULT_METHOD,
  method_data_from_address: '',
  method_data_message_attach: ATTACH_MESSAGE_DEFAULT,
  method_data_message: INCLUDE_MESSAGE_DEFAULT,
  method_data_notice: DEFAULT_NOTICE,
  method_data_notice_attach_format: DEFAULT_NOTICE_ATTACH_FORMAT,
  method_data_notice_report_format: DEFAULT_NOTICE_REPORT_FORMAT,
  method_data_scp_path: DEFAULT_SCP_PATH,
  method_data_scp_host: '',
  method_data_scp_port: 22,
  method_data_scp_known_hosts: '',
  method_data_smb_file_path: 'report.xml',
  method_data_smb_share_path: '\\\\localhost\\gvm-reports',
  method_data_snmp_agent: 'localhost',
  method_data_snmp_community: '',
  method_data_snmp_community_configured: '0',
  method_data_snmp_message: '$e',
  method_data_status: 'Done',
  method_data_subject: TASK_SUBJECT,
  method_data_to_address: '',
  name: _('Unnamed'),
  report_formats: [],
  result_filters: [],
  secinfo_filters: [],
};

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
    if (onValueChange) {
      onValueChange(CONDITION_TYPE_ALWAYS, 'condition'); // reset condition
    }
    // in addition to changing the event in the dialog, change it here as well
    // to have it handy in render()
    this.setState({stateEvent: value});
  }

  render() {
    const {
      alert,
      credentials,
      filter_id,
      title = _('New Alert'),
      report_formats,
      method_data_recipient_credential,
      method_data_scp_credential,
      method_data_smb_credential,
      onClose,
      onEmailCredentialChange,
      onNewEmailCredentialClick,
      onNewScpCredentialClick,
      onNewSmbCredentialClick,
      onSave,
      onScpCredentialChange,
      onSmbCredentialChange,
      ...props
    } = this.props;

    const {stateEvent: event} = this.state;

    const methodTypes = [];

    methodTypes.push(
      {value: METHOD_TYPE_EMAIL, label: _('Email')},
      {value: METHOD_TYPE_SCP, label: _('SCP')},
      {value: METHOD_TYPE_SMB, label: _('SMB')},
      {value: METHOD_TYPE_SNMP, label: _('SNMP')},
      {value: METHOD_TYPE_START_TASK, label: _('Start Task')},
      {value: METHOD_TYPE_SYSLOG, label: _('System Logger')},
    );

    const data = {
      ...DEFAULTS,
      ...alert,
    };

    for (const [key, value] of Object.entries(props)) {
      if (isDefined(value)) {
        data[key] = value;
      }
    }

    const controlledValues = {
      event,
      filter_id,
      method_data_recipient_credential,
      method_data_scp_credential,
      method_data_smb_credential,
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
              </FormGroup>

              <FormGroup title={_('Condition')}>
                <Radio
                  checked={values.condition === CONDITION_TYPE_ALWAYS}
                  name="condition"
                  title={_('Always')}
                  value={CONDITION_TYPE_ALWAYS}
                  onChange={onValueChange}
                />
              </FormGroup>

              <FormGroup title={_('Method')}>
                <Select
                  items={methodTypes}
                  name="method"
                  value={values.method}
                  onChange={value => {
                    if (
                      values.method === METHOD_TYPE_SNMP &&
                      value !== METHOD_TYPE_SNMP
                    ) {
                      onValueChange('', 'method_data_snmp_community');
                    }
                    onValueChange(value, 'method');
                  }}
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
                  noticeAttachFormat={values.method_data_notice_attach_format}
                  noticeReportFormat={values.method_data_notice_report_format}
                  prefix="method_data"
                  recipientCredential={values.method_data_recipient_credential}
                  reportFormats={report_formats}
                  subject={values.method_data_subject}
                  toAddress={values.method_data_to_address}
                  onChange={onValueChange}
                  onCredentialChange={onEmailCredentialChange}
                  onNewCredentialClick={onNewEmailCredentialClick}
                  onSave={onSave}
                />
              )}

              {values.method === METHOD_TYPE_SCP && (
                <ScpMethodPart
                  credentials={credentials}
                  prefix="method_data"
                  reportFormats={report_formats}
                  scpCredential={values.method_data_scp_credential}
                  scpHost={values.method_data_scp_host}
                  scpKnownHosts={values.method_data_scp_known_hosts}
                  scpPath={values.method_data_scp_path}
                  scpPort={values.method_data_scp_port}
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
                  reportFormats={report_formats}
                  smbCredential={values.method_data_smb_credential}
                  smbFilePath={values.method_data_smb_file_path}
                  smbMaxProtocol={values.method_data_smb_max_protocol}
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
  alert: PropTypes.model,
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
  expected_revision: PropTypes.string,
  filter_id: PropTypes.idOrZero,
  method: PropTypes.string,
  method_data_from_address: PropTypes.string,
  method_data_message: PropTypes.string,
  method_data_message_attach: PropTypes.string,
  method_data_notice: PropTypes.string,
  method_data_notice_attach_format: PropTypes.id,
  method_data_notice_report_format: PropTypes.id,
  method_data_recipient_credential: PropTypes.id,
  method_data_scp_credential: PropTypes.id,
  method_data_scp_host: PropTypes.string,
  method_data_scp_known_hosts: PropTypes.string,
  method_data_scp_path: PropTypes.string,
  method_data_scp_port: PropTypes.number,
  method_data_scp_report_format: PropTypes.id,
  method_data_smb_credential: PropTypes.id,
  method_data_smb_file_path: PropTypes.string,
  method_data_smb_report_format: PropTypes.id,
  method_data_smb_share_path: PropTypes.string,
  method_data_snmp_agent: PropTypes.string,
  method_data_snmp_community: PropTypes.string,
  method_data_snmp_message: PropTypes.string,
  method_data_start_task_task: PropTypes.id,
  method_data_subject: PropTypes.string,
  method_data_to_address: PropTypes.string,
  name: PropTypes.string,
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
  onSave: PropTypes.func.isRequired,
  onScpCredentialChange: PropTypes.func.isRequired,
  onSmbCredentialChange: PropTypes.func.isRequired,
};

export default AlertDialog;

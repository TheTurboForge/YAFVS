/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import AlertCommand from 'gmp/commands/alert';
import {
  createActionResultResponse,
  createEntityResponse,
  createHttp,
  createResponse,
} from 'gmp/commands/testing';
import {
  CONDITION_TYPE_ALWAYS,
  CONDITION_TYPE_SEVERITY_AT_LEAST,
  EVENT_TYPE_NEW_SECINFO,
  EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
  METHOD_TYPE_EMAIL,
  METHOD_TYPE_SCP,
  METHOD_TYPE_SMB,
} from 'gmp/models/alert';
import {YES_VALUE} from 'gmp/parser';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const nativeJsonResponse = (payload: unknown, status = 200) => ({
  json: testing.fn().mockResolvedValue(payload),
  ok: status >= 200 && status < 300,
  status,
});

describe('AlertCommand tests', () => {
  test('should get an alert through GMP when native API is unavailable', async () => {
    const response = createEntityResponse('alert', {_id: 'foo'});
    const fakeHttp = createHttp(response);
    const cmd = new AlertCommand(fakeHttp);
    const result = await cmd.get({id: 'target_id1'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_alert',
        alert_id: 'target_id1',
      },
    });
    expect(result.data.id).toEqual('foo');
  });

  test('should get an alert through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'alert_id1',
        name: 'Native Alert',
        comment: 'redacted metadata only',
        active: true,
        method_data_redacted: true,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new AlertCommand(fakeHttp);

    const result = await cmd.get({id: 'alert_id1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/alerts/alert_id1', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts/alert_id1',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data.id).toEqual('alert_id1');
    expect(result.data.name).toEqual('Native Alert');
    expect(result.data.comment).toEqual('redacted metadata only');
  });

  test('should not fall back to GMP when native alert detail fails', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'not found'}}),
      ok: false,
      status: 404,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new AlertCommand(fakeHttp);

    await expect(cmd.get({id: 'missing-alert'})).rejects.toThrow(
      'Native API request failed with status 404',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should export alert metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'alert_id1',
        name: 'Alert',
        method_data_redacted: true,
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new AlertCommand(fakeHttp);

    const result = await cmd.export({id: 'alert_id1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/alerts/alert_id1/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts/alert_id1/export',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(JSON.parse(result.data)).toEqual({
      id: 'alert_id1',
      name: 'Alert',
      method_data_redacted: true,
    });
  });

  test('should allow to clone an alert', async () => {
    const response = createActionResultResponse({id: 'cloned_id'});
    const fakeHttp = createHttp(response);
    const cmd = new AlertCommand(fakeHttp);
    const result = await cmd.clone({id: 'target_id1'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'clone',
        id: 'target_id1',
        resource_type: 'alert',
      },
    });
    expect(result.data.id).toEqual('cloned_id');
  });

  test('should clone an alert through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'native-cloned-alert-id'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new AlertCommand(fakeHttp);

    const result = await cmd.clone({id: 'alert_id1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/alerts/alert_id1/clone',
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts/alert_id1/clone',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({}),
      },
    );
    expect(result.data.id).toEqual('native-cloned-alert-id');
  });

  test('should not fall back to GMP when native alert clone fails', async () => {
    const response = createActionResultResponse({id: 'fallback-cloned-id'});
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({error: {message: 'disabled'}}),
      ok: false,
      status: 503,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    const cmd = new AlertCommand(fakeHttp);

    await expect(cmd.clone({id: 'alert_id1'})).rejects.toThrow(
      'Native API request failed with status 503',
    );
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should allow to delete an alert', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new AlertCommand(fakeHttp);
    const result = await cmd.delete({id: 'target_id1'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_alert',
        alert_id: 'target_id1',
      },
    });
    expect(result).toBeUndefined();
  });

  test('should delete an alert through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      ok: true,
      status: 204,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new AlertCommand(fakeHttp);

    await cmd.delete({id: 'alert_id1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/alerts/alert_id1');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts/alert_id1',
      {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should not fall back to GMP when native alert delete fails', async () => {
    const response = createActionResultResponse();
    const fetchMock = testing.fn().mockResolvedValue({
      ok: false,
      status: 409,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    const cmd = new AlertCommand(fakeHttp);

    await expect(cmd.delete({id: 'alert_id1'})).rejects.toThrow(
      'Native API request failed with status 409',
    );
    expect(fetchMock).toHaveBeenCalled();
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should create alert', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new AlertCommand(fakeHttp);
    const resp = await cmd.create({
      name: 'Test Alert',
      comment: 'This is a test alert',
      event: EVENT_TYPE_NEW_SECINFO,
      condition: CONDITION_TYPE_ALWAYS,
      filter_id: 'filter_id1',
      method: METHOD_TYPE_EMAIL,
      active: true,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'create_alert',
        name: 'Test Alert',
        comment: 'This is a test alert',
        active: YES_VALUE,
        event: EVENT_TYPE_NEW_SECINFO,
        condition: CONDITION_TYPE_ALWAYS,
        filter_id: 'filter_id1',
        method: METHOD_TYPE_EMAIL,
      },
    });
    expect(resp.data.id).toEqual('foo');
  });

  test('should create a simple EMAIL alert through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse({id: 'native-alert-id'}, 201));
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new AlertCommand(fakeHttp);

    const result = await cmd.create({
      active: '1',
      name: 'Simple email',
      comment: 'delivery details remain write-only',
      event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      condition: CONDITION_TYPE_ALWAYS,
      filter_id: 0,
      method: METHOD_TYPE_EMAIL,
      event_data_status: 'Done',
      method_data_to_address: '[REDACTED TO]',
      method_data_from_address: '[REDACTED FROM]',
      method_data_subject: '[REDACTED SUBJECT]',
      method_data_notice: '1',
      method_data_recipient_credential: '0',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts',
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          method: 'EMAIL',
          name: 'Simple email',
          comment: 'delivery details remain write-only',
          active: true,
          status: 'Done',
          to_address: '[REDACTED TO]',
          from_address: '[REDACTED FROM]',
          subject: '[REDACTED SUBJECT]',
          notice: 'simple',
        }),
      },
    );
    expect(result.data).toEqual({id: 'native-alert-id'});
  });

  test('should create an include EMAIL alert through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse({id: 'native-alert-id'}, 201));
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    const cmd = new AlertCommand(fakeHttp);

    await cmd.create({
      active: false,
      name: 'Include email',
      event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      condition: CONDITION_TYPE_ALWAYS,
      method: METHOD_TYPE_EMAIL,
      event_data_status: 'Stopped',
      method_data_to_address: '[REDACTED TO]',
      method_data_subject: '[REDACTED SUBJECT]',
      method_data_notice: '0',
      method_data_recipient_credential: 'recipient-id',
      method_data_notice_report_format: 'format-id',
      method_data_notice_report_config: 0,
      method_data_message: '[REDACTED MESSAGE]',
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts',
      expect.objectContaining({
        body: JSON.stringify({
          method: 'EMAIL',
          name: 'Include email',
          comment: '',
          active: false,
          status: 'Stopped',
          to_address: '[REDACTED TO]',
          subject: '[REDACTED SUBJECT]',
          recipient_credential_id: 'recipient-id',
          notice: 'include',
          report_format_id: 'format-id',
          message: '[REDACTED MESSAGE]',
        }),
      }),
    );
  });

  test('should create an attach EMAIL alert through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse({id: 'native-alert-id'}, 201));
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    const cmd = new AlertCommand(fakeHttp);

    await cmd.create({
      active: true,
      name: 'Attach email',
      event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      condition: CONDITION_TYPE_ALWAYS,
      method: METHOD_TYPE_EMAIL,
      event_data_status: 'Interrupted',
      method_data_to_address: '[REDACTED TO]',
      method_data_subject: '[REDACTED SUBJECT]',
      method_data_notice: '2',
      method_data_notice_attach_format: 'format-id',
      method_data_notice_attach_config: 'config-id',
      method_data_message_attach: '[REDACTED MESSAGE]',
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts',
      expect.objectContaining({
        body: JSON.stringify({
          method: 'EMAIL',
          name: 'Attach email',
          comment: '',
          active: true,
          status: 'Interrupted',
          to_address: '[REDACTED TO]',
          subject: '[REDACTED SUBJECT]',
          notice: 'attach',
          report_format_id: 'format-id',
          report_config_id: 'config-id',
          message: '[REDACTED MESSAGE]',
        }),
      }),
    );
  });

  test('should create an SMB alert through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse({id: 'native-alert-id'}, 201));
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    const cmd = new AlertCommand(fakeHttp);

    await cmd.create({
      active: '0',
      name: 'SMB alert',
      event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      condition: CONDITION_TYPE_ALWAYS,
      filter_id: '0',
      method: METHOD_TYPE_SMB,
      event_data_status: 'Done',
      method_data_smb_credential: 'credential-id',
      method_data_smb_share_path: '[REDACTED SHARE]',
      method_data_smb_file_path: '[REDACTED FILE]',
      method_data_smb_report_format: 'format-id',
      method_data_smb_report_config: 0,
      method_data_smb_max_protocol: '',
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts',
      expect.objectContaining({
        body: JSON.stringify({
          method: 'SMB',
          name: 'SMB alert',
          comment: '',
          active: false,
          status: 'Done',
          smb_credential_id: 'credential-id',
          smb_share_path: '[REDACTED SHARE]',
          smb_file_path: '[REDACTED FILE]',
          report_format_id: 'format-id',
          smb_max_protocol: 'default',
        }),
      }),
    );
  });

  test.each([
    ['empty filter id', ''],
    ['missing filter id', undefined],
  ])(
    'should treat %s as no filter for native alert creation',
    async (_label, filterId) => {
      const fetchMock = testing
        .fn()
        .mockResolvedValue(nativeJsonResponse({id: 'native-alert-id'}, 201));
      testing.stubGlobal('fetch', fetchMock);
      const fakeHttp = createHttp(undefined) as ReturnType<
        typeof createHttp
      > & {
        buildUrl: ReturnType<typeof testing.fn>;
        session: ReturnType<typeof createSession>;
      };
      fakeHttp.buildUrl = testing.fn(
        (path: string) => `https://turbovas.example/${path}`,
      );
      fakeHttp.session = createSession();
      const cmd = new AlertCommand(fakeHttp);

      await cmd.create({
        active: '1',
        name: 'No filter email',
        event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
        condition: CONDITION_TYPE_ALWAYS,
        filter_id: filterId,
        method: METHOD_TYPE_EMAIL,
        event_data_status: 'Done',
        method_data_to_address: '[REDACTED TO]',
        method_data_subject: '[REDACTED SUBJECT]',
        method_data_notice: '1',
      });

      expect(fetchMock).toHaveBeenCalledOnce();
      expect(fakeHttp.request).not.toHaveBeenCalled();
    },
  );

  test('should keep unsupported alert create semantics on GMP', async () => {
    const response = createActionResultResponse();
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    const cmd = new AlertCommand(fakeHttp);

    await cmd.create({
      active: true,
      name: 'Unsupported event',
      event: EVENT_TYPE_NEW_SECINFO,
      condition: CONDITION_TYPE_ALWAYS,
      method: METHOD_TYPE_EMAIL,
    });
    await cmd.create({
      active: true,
      name: 'Unsupported condition',
      event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      condition: CONDITION_TYPE_SEVERITY_AT_LEAST,
      method: METHOD_TYPE_EMAIL,
    });
    await cmd.create({
      active: true,
      name: 'Unsupported method',
      event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      condition: CONDITION_TYPE_ALWAYS,
      method: METHOD_TYPE_SCP,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledTimes(3);
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: expect.objectContaining({
        cmd: 'create_alert',
        event: EVENT_TYPE_NEW_SECINFO,
        condition: CONDITION_TYPE_ALWAYS,
      }),
    });
  });

  test('should not fall back to GMP after native alert create errors', async () => {
    const response = createActionResultResponse();
    const fetchMock = testing
      .fn()
      .mockResolvedValue(
        nativeJsonResponse({error: {message: 'rejected'}}, 422),
      );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    const cmd = new AlertCommand(fakeHttp);

    await expect(
      cmd.create({
        active: true,
        name: 'Rejected alert',
        event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
        condition: CONDITION_TYPE_ALWAYS,
        method: METHOD_TYPE_EMAIL,
        event_data_status: 'Done',
        method_data_to_address: '[REDACTED TO]',
        method_data_subject: '[REDACTED SUBJECT]',
        method_data_notice: '1',
      }),
    ).rejects.toThrow('Native API request failed with status 422');
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test.each([
    [
      'committed_response_unavailable',
      'The mutation committed, but its response could not be completed; verify current state before retrying.',
    ],
    [
      'mutation_outcome_indeterminate',
      'The mutation may have committed, but no authoritative response was received; verify current state before retrying.',
    ],
  ])(
    'preserves redacted native alert error code %s without payload',
    async (code, apiMessage) => {
      const response = createActionResultResponse();
      const fetchMock = testing.fn().mockResolvedValue(
        nativeJsonResponse(
          {
            error: {
              code,
              message: apiMessage,
              delivery_payload: '[REDACTED DELIVERY PAYLOAD]',
            },
          },
          502,
        ),
      );
      testing.stubGlobal('fetch', fetchMock);
      const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
        buildUrl: ReturnType<typeof testing.fn>;
        session: ReturnType<typeof createSession>;
      };
      fakeHttp.buildUrl = testing.fn(
        (path: string) => `https://turbovas.example/${path}`,
      );
      fakeHttp.session = createSession();
      const cmd = new AlertCommand(fakeHttp);

      let caught: unknown;
      try {
        await cmd.create({
          active: '1',
          name: 'Indeterminate alert',
          event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
          condition: CONDITION_TYPE_ALWAYS,
          filter_id: 0,
          method: METHOD_TYPE_EMAIL,
          event_data_status: 'Done',
          method_data_to_address: '[REDACTED TO]',
          method_data_subject: '[REDACTED SUBJECT]',
          method_data_notice: '1',
        });
      } catch (error) {
        caught = error;
      }

      expect(caught).toMatchObject({
        code,
        message: `Native API request failed with status 502: ${code}: ${apiMessage}`,
      });
      expect(caught).not.toHaveProperty('payload');
      expect((caught as Error).message).not.toContain('DELIVERY PAYLOAD');
      expect(fakeHttp.request).not.toHaveBeenCalled();
    },
  );

  test('should send missing and invalid native alert delivery fields for typed rejection', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(
        nativeJsonResponse({error: {message: 'rejected'}}, 400),
      );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    const cmd = new AlertCommand(fakeHttp);

    await expect(
      cmd.create({
        active: true,
        name: 'Invalid native alert',
        event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
        condition: CONDITION_TYPE_ALWAYS,
        method: METHOD_TYPE_EMAIL,
        event_data_status: 'Done',
        method_data_subject: '[REDACTED SUBJECT]',
        method_data_notice: 'unexpected-notice',
      }),
    ).rejects.toThrow('Native API request failed with status 400');

    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts',
      expect.objectContaining({
        body: JSON.stringify({
          method: 'EMAIL',
          name: 'Invalid native alert',
          comment: '',
          active: true,
          status: 'Done',
          subject: '[REDACTED SUBJECT]',
          notice: 'unexpected-notice',
        }),
      }),
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should save alert', async () => {
    const response = createActionResultResponse();
    const fakeHttp = createHttp(response);
    const cmd = new AlertCommand(fakeHttp);
    const resp = await cmd.save({
      id: 'target_id1',
      name: 'Test Alert',
      comment: 'This is a test alert',
      event: EVENT_TYPE_NEW_SECINFO,
      condition: CONDITION_TYPE_ALWAYS,
      filter_id: 'filter_id1',
      method: METHOD_TYPE_EMAIL,
      active: true,
    });
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'save_alert',
        alert_id: 'target_id1',
        name: 'Test Alert',
        comment: 'This is a test alert',
        active: YES_VALUE,
        event: EVENT_TYPE_NEW_SECINFO,
        condition: CONDITION_TYPE_ALWAYS,
        filter_id: 'filter_id1',
        method: METHOD_TYPE_EMAIL,
      },
    });
    const {data} = resp;
    expect(data.id).toEqual('foo');
  });

  test('should save alert metadata through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'alert_id1', name: 'updated'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new AlertCommand(fakeHttp);

    const result = await cmd.save({
      id: 'alert_id1',
      name: 'updated',
      comment: 'metadata only',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/alerts/alert_id1');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/alerts/alert_id1',
      {
        method: 'PATCH',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
        body: JSON.stringify({
          name: 'updated',
          comment: 'metadata only',
        }),
      },
    );
    expect(result.data.id).toEqual('alert_id1');
  });

  test('should keep delivery alert saves on GMP when native API is available', async () => {
    const response = createActionResultResponse();
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(response) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    const cmd = new AlertCommand(fakeHttp);

    await cmd.save({
      id: 'alert_id1',
      name: 'Test Alert',
      comment: 'This is a test alert',
      event: EVENT_TYPE_NEW_SECINFO,
      condition: CONDITION_TYPE_ALWAYS,
      filter_id: 'filter_id1',
      method: METHOD_TYPE_EMAIL,
      active: true,
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: expect.objectContaining({
        cmd: 'save_alert',
        alert_id: 'alert_id1',
        event: EVENT_TYPE_NEW_SECINFO,
        method: METHOD_TYPE_EMAIL,
      }),
    });
  });

  test('should allow to get new alert settings', async () => {
    const response = createResponse({
      new_alert: {
        get_report_formats_response: {
          report_format: [{_id: 'rf1'}, {_id: 'rf2'}],
        },
        get_report_configs_response: {
          report_config: [{_id: 'rc1'}, {_id: 'rc2'}],
        },
        get_credentials_response: {
          credential: [{_id: 'cr1'}, {_id: 'cr2'}],
        },
        get_tasks_response: {
          task: [{_id: 't1'}, {_id: 't2'}],
        },
        get_filters_response: {
          filter: [{_id: 'f1'}, {_id: 'f2'}],
        },
      },
    });
    const fakeHttp = createHttp(response);
    const cmd = new AlertCommand(fakeHttp);
    const resp = await cmd.newAlertSettings();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'new_alert',
      },
    });
    expect(resp.data.report_formats.length).toBe(2);
    expect(resp.data.report_configs.length).toBe(2);
    expect(resp.data.credentials.length).toBe(2);
    expect(resp.data.tasks.length).toBe(2);
    expect(resp.data.filters.length).toBe(2);
  });

  test('should get new alert settings through native API when available', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        nativeJsonResponse({items: [{id: 'rf1', name: 'PDF'}]}),
      )
      .mockResolvedValueOnce(
        nativeJsonResponse({items: [{id: 'rc1', name: 'Default config'}]}),
      )
      .mockResolvedValueOnce(
        nativeJsonResponse({items: [{id: 'cr1', name: 'Credential'}]}),
      )
      .mockResolvedValueOnce(
        nativeJsonResponse({items: [{id: 't1', name: 'Task'}]}),
      )
      .mockResolvedValueOnce(
        nativeJsonResponse({
          items: [{id: 'f1', name: 'Task filter', filter_type: 'task'}],
        }),
      );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new AlertCommand(fakeHttp);

    const resp = await cmd.newAlertSettings();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-formats',
      expect.objectContaining({page: 1, page_size: 500, sort: 'name'}),
    );
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/report-configs',
      expect.objectContaining({page: 1, page_size: 500, sort: 'name'}),
    );
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/credentials',
      expect.objectContaining({page: 1, page_size: 500, sort: 'name'}),
    );
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tasks',
      expect.objectContaining({page: 1, page_size: 500, sort: 'name'}),
    );
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/filters',
      expect.objectContaining({page: 1, page_size: 500, sort: 'name'}),
    );
    expect(resp.data.report_formats.length).toBe(1);
    expect(resp.data.report_configs.length).toBe(1);
    expect(resp.data.credentials.length).toBe(1);
    expect(resp.data.tasks.length).toBe(1);
    expect(resp.data.filters.length).toBe(1);
  });

  test('should allow to get edit alert settings', async () => {
    const response = createResponse({
      edit_alert: {
        get_alerts_response: {
          alert: {_id: 'a1'},
        },
        get_report_formats_response: {
          report_format: [{_id: 'rf1'}, {_id: 'rf2'}],
        },
        get_report_configs_response: {
          report_config: [{_id: 'rc1'}, {_id: 'rc2'}],
        },
        get_credentials_response: {
          credential: [{_id: 'cr1'}, {_id: 'cr2'}],
        },
        get_tasks_response: {
          task: [{_id: 't1'}, {_id: 't2'}],
        },
        get_filters_response: {
          filter: [{_id: 'f1'}, {_id: 'f2'}],
        },
      },
    });
    const fakeHttp = createHttp(response);
    const cmd = new AlertCommand(fakeHttp);
    const resp = await cmd.editAlertSettings({id: 'alert_id1'});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'edit_alert',
        alert_id: 'alert_id1',
      },
    });
    expect(resp.data.alert.id).toBe('a1');
    expect(resp.data.report_formats.length).toBe(2);
    expect(resp.data.report_configs.length).toBe(2);
    expect(resp.data.credentials.length).toBe(2);
    expect(resp.data.tasks.length).toBe(2);
    expect(resp.data.filters.length).toBe(2);
  });

  test('should get edit alert settings through native API when available', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        nativeJsonResponse({
          id: 'alert_id1',
          name: 'Native Alert',
          active: true,
          method_data_redacted: true,
        }),
      )
      .mockResolvedValueOnce(
        nativeJsonResponse({items: [{id: 'rf1', name: 'PDF'}]}),
      )
      .mockResolvedValueOnce(
        nativeJsonResponse({items: [{id: 'rc1', name: 'Default config'}]}),
      )
      .mockResolvedValueOnce(
        nativeJsonResponse({items: [{id: 'cr1', name: 'Credential'}]}),
      )
      .mockResolvedValueOnce(
        nativeJsonResponse({items: [{id: 't1', name: 'Task'}]}),
      )
      .mockResolvedValueOnce(
        nativeJsonResponse({
          items: [{id: 'f1', name: 'Task filter', filter_type: 'task'}],
        }),
      );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
      buildUrl: ReturnType<typeof testing.fn>;
      session: ReturnType<typeof createSession>;
    };
    fakeHttp.buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    fakeHttp.session = createSession();
    fakeHttp.session.token = 'test-token';
    fakeHttp.session.jwt = 'jwt-token';
    const cmd = new AlertCommand(fakeHttp);

    const resp = await cmd.editAlertSettings({id: 'alert_id1'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/alerts/alert_id1', {
      token: 'test-token',
    });
    expect(resp.data.alert.id).toBe('alert_id1');
    expect(resp.data.report_formats.length).toBe(1);
    expect(resp.data.report_configs.length).toBe(1);
    expect(resp.data.credentials.length).toBe(1);
    expect(resp.data.tasks.length).toBe(1);
    expect(resp.data.filters.length).toBe(1);
  });
});

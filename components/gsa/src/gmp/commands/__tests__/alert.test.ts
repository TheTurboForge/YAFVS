/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import AlertCommand from 'gmp/commands/alert';
import {createHttp} from 'gmp/commands/testing';
import {
  type AlertConditionType,
  type AlertEventType,
  CONDITION_TYPE_ALWAYS,
  CONDITION_TYPE_SEVERITY_AT_LEAST,
  EVENT_TYPE_NEW_SECINFO,
  EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
  METHOD_TYPE_EMAIL,
  METHOD_TYPE_SNMP,
  METHOD_TYPE_START_TASK,
} from 'gmp/models/alert';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const nativeJsonResponse = (payload: unknown, status = 200) => ({
  json: testing.fn().mockResolvedValue(payload),
  ok: status >= 200 && status < 300,
  status,
});

const createNativeHttp = () => {
  const http = createHttp(undefined) as ReturnType<typeof createHttp> & {
    buildUrl: ReturnType<typeof testing.fn>;
    session: ReturnType<typeof createSession>;
  };
  http.buildUrl = testing.fn((path: string) => `https://yafvs.example/${path}`);
  http.session = createSession();
  http.session.token = 'test-token';
  http.session.jwt = 'jwt-token';
  return http;
};

const snmpDefinition = {
  revision: '7',
  method: 'SNMP' as const,
  name: 'Configured SNMP alert',
  comment: 'community is intentionally absent',
  active: true,
  status: 'Done',
  snmp_agent: 'localhost',
  snmp_message: '$e',
  snmp_community_configured: true,
};

describe('AlertCommand native definition tests', () => {
  test('gets and hydrates a retained definition without exposing SNMP community', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse(snmpDefinition));
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();

    const result = await new AlertCommand(http).get({id: 'alert-id'});

    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenCalledWith(
      'api/v1/alerts/alert-id/definition',
      {token: 'test-token'},
    );
    expect(result.data.method?.type).toBe('SNMP');
    expect(result.data.method?.data.snmp_community).toBeUndefined();
    expect(result.data.method?.data.snmp_community_configured?.value).toBe('1');
    expect(
      (result.data as typeof result.data & {definitionRevision?: string})
        .definitionRevision,
    ).toBe('7');
  });

  test('creates a retained alert through the typed native endpoint', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse({id: 'alert-id'}, 201));
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();

    await new AlertCommand(http).create({
      active: true,
      name: 'Follow-up task',
      event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      condition: CONDITION_TYPE_ALWAYS,
      filter_id: 0,
      method: METHOD_TYPE_START_TASK,
      event_data_status: 'Done',
      method_data_start_task_task: 'task-id',
    });

    expect(http.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/alerts',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          method: 'START_TASK',
          name: 'Follow-up task',
          comment: '',
          active: true,
          status: 'Done',
          task_id: 'task-id',
        }),
      }),
    );
  });

  test.each([
    [EVENT_TYPE_NEW_SECINFO, CONDITION_TYPE_ALWAYS, 0, 'event'],
    [
      EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      CONDITION_TYPE_SEVERITY_AT_LEAST,
      0,
      'condition',
    ],
    [
      EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      CONDITION_TYPE_ALWAYS,
      'filter-id',
      'filter',
    ],
  ])(
    'rejects unsupported retained %s locally',
    async (event, condition, filterId, reason) => {
      const fetchMock = testing.fn();
      testing.stubGlobal('fetch', fetchMock);
      const http = createNativeHttp();

      expect(() =>
        new AlertCommand(http).create({
          active: true,
          name: 'Unsupported alert',
          event: event as AlertEventType,
          condition: condition as AlertConditionType,
          filter_id: filterId,
          method: METHOD_TYPE_EMAIL,
          event_data_status: 'Done',
          method_data_to_address: 'operator@example.test',
          method_data_notice: '1',
        }),
      ).toThrow(`Unsupported native alert definition: ${reason}`);
      expect(fetchMock).not.toHaveBeenCalled();
      expect(http.request).not.toHaveBeenCalled();
    },
  );

  test('preserves a configured SNMP community when its hydrated input remains blank', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse(snmpDefinition));
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();

    await new AlertCommand(http).save({
      id: 'alert-id',
      expected_revision: '7',
      active: true,
      name: 'Configured SNMP alert',
      comment: 'updated',
      event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      condition: CONDITION_TYPE_ALWAYS,
      filter_id: 0,
      method: METHOD_TYPE_SNMP,
      event_data_status: 'Done',
      method_data_snmp_agent: 'localhost',
      method_data_snmp_community: '',
      method_data_snmp_community_configured: '1',
      method_data_snmp_message: '$e',
    });

    expect(http.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/alerts/alert-id/definition',
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({
          expected_revision: '7',
          definition: {
            method: 'SNMP',
            name: 'Configured SNMP alert',
            comment: 'updated',
            active: true,
            status: 'Done',
            snmp_agent: 'localhost',
            snmp_message: '$e',
            snmp_community_mode: 'preserve',
          },
        }),
      }),
    );
  });

  test('replaces an SNMP community only with a nonblank explicit value', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse(snmpDefinition));
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();

    await new AlertCommand(http).save({
      id: 'alert-id',
      expected_revision: '7',
      active: true,
      name: 'Configured SNMP alert',
      event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      condition: CONDITION_TYPE_ALWAYS,
      method: METHOD_TYPE_SNMP,
      event_data_status: 'Done',
      method_data_snmp_agent: 'localhost',
      method_data_snmp_community: '[REDACTED COMMUNITY]',
      method_data_snmp_community_configured: '1',
      method_data_snmp_message: '$e',
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/alerts/alert-id/definition',
      expect.objectContaining({
        body: expect.stringContaining('"snmp_community_mode":"replace"'),
      }),
    );
  });

  test('rejects a new or switched SNMP method without an explicit community', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();

    expect(() =>
      new AlertCommand(http).create({
        active: true,
        name: 'New SNMP alert',
        event: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
        condition: CONDITION_TYPE_ALWAYS,
        method: METHOD_TYPE_SNMP,
        event_data_status: 'Done',
        method_data_snmp_agent: 'localhost',
        method_data_snmp_community: '',
        method_data_snmp_community_configured: '0',
        method_data_snmp_message: '$e',
      }),
    ).toThrow('Unsupported native alert definition: SNMP community');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('uses the narrow metadata PATCH for metadata-only saves', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        nativeJsonResponse({id: 'alert-id', name: 'Renamed alert'}),
      );
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();

    await new AlertCommand(http).save({
      id: 'alert-id',
      name: 'Renamed alert',
      comment: 'metadata update',
    });

    expect(http.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/alerts/alert-id',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          name: 'Renamed alert',
          comment: 'metadata update',
        }),
      }),
    );
  });

  test('uses native definition and lookup reads for edit settings', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(nativeJsonResponse({items: []}));
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    fetchMock.mockResolvedValueOnce(nativeJsonResponse(snmpDefinition));

    const result = await new AlertCommand(http).editAlertSettings({
      id: 'alert-id',
    });

    expect(http.request).not.toHaveBeenCalled();
    expect(result.data.alert.id).toBe('alert-id');
    expect(http.buildUrl).toHaveBeenCalledWith(
      'api/v1/alerts/alert-id/definition',
      {token: 'test-token'},
    );
  });

  test('uses native endpoints for clone, delete, test, and export', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(nativeJsonResponse({id: 'cloned-id'}))
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce(
        nativeJsonResponse({id: 'alert-id', method: 'EMAIL'}),
      );
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new AlertCommand(http);

    await command.clone({id: 'alert-id'});
    await command.delete({id: 'alert-id'});
    await command.test({id: 'alert-id'});
    await command.export({id: 'alert-id'});

    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenCalledWith('api/v1/alerts/alert-id/clone');
    expect(http.buildUrl).toHaveBeenCalledWith('api/v1/alerts/alert-id');
    expect(http.buildUrl).toHaveBeenCalledWith('api/v1/alerts/alert-id/test');
    expect(http.buildUrl).toHaveBeenCalledWith(
      'api/v1/alerts/alert-id/export',
      {token: 'test-token'},
    );
  });
});

/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {createResponse, createHttp} from 'gmp/commands/testing';
import TrashCanCommand from 'gmp/commands/trashcan';

describe('TrashCanCommand tests', () => {
  test('should allow to restore an entity', async () => {
    const response = createResponse({});
    const fakeHttp = createHttp(response);
    const cmd = new TrashCanCommand(fakeHttp);
    await cmd.restore({id: '1234'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'restore',
        target_id: '1234',
      },
    });
  });

  test('should allow to empty the trashcan', async () => {
    const response = createResponse({});
    const fakeHttp = createHttp(response);
    const cmd = new TrashCanCommand(fakeHttp);
    await cmd.empty();
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {cmd: 'empty_trashcan'},
    });
  });

  test('should allow to delete an entity from the trashcan', async () => {
    const response = createResponse({});
    const fakeHttp = createHttp(response);
    const cmd = new TrashCanCommand(fakeHttp);
    await cmd.delete({id: '1234', entityType: 'task'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_from_trash',
        task_id: '1234',
        resource_type: 'task',
      },
    });
  });

  test('should allow to delete an host from the trashcan', async () => {
    const response = createResponse({});
    const fakeHttp = createHttp(response);
    const cmd = new TrashCanCommand(fakeHttp);
    await cmd.delete({id: '1234', entityType: 'host'});
    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'delete_from_trash',
        asset_id: '1234',
        resource_type: 'asset',
      },
    });
  });



  test('should handle failed requests gracefully', async () => {
    const response = createResponse({
      get_trash: {
        get_alerts_response: {
          alert: [{_id: 'alert1'}],
        },
      },
    });

    const fakeHttp = createHttp(response);
    const cmd = new TrashCanCommand(fakeHttp);
    const data = await cmd.get();

    expect(data.data.alerts.length).toBe(1);
    expect(data.data.scanConfigs.length).toBe(0);

    expect(data.data).toHaveProperty('failedRequests');
  });
});

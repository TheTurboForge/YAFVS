/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {fireEvent, rendererWith, screen, wait} from 'web/testing';
import Features from 'gmp/capabilities/features';
import {createActionResultResponse} from 'gmp/commands/testing';
import Response from 'gmp/http/response';
import Setting from 'gmp/models/setting';
import Task from 'gmp/models/task';
import {createSession} from 'gmp/testing';
import Button from 'web/components/form/Button';
import TaskComponent, {
  isTaskMetadataOnlyDialogSave,
} from 'web/pages/tasks/TaskComponent';

const createGmp = ({
  alerts = [],
  targets = [],
  schedules = [],
  scanConfigs = [],
  scanners = [],
  credentials = [],
  tags = [],
} = {}) => {
  return {
    settings: {
      enableGreenboneSensor: true,
      enableKrb5: false,
    },
    session: createSession(),
    user: {
      currentSettings: testing.fn().mockResolvedValue(
        new Response({
          detailsexportfilename: new Setting({
            _id: 'a6ac88c5-729c-41ba-ac0a-deea4a3441f2',
            name: 'Details Export File Name',
            value: '%T-%U',
          }),
        }),
      ),
    },
    alerts: {
      getAll: testing.fn().mockResolvedValue(new Response(alerts)),
      get: testing.fn().mockResolvedValue({data: alerts, meta: {filter: {}}}),
    },
    targets: {
      getAll: testing.fn().mockResolvedValue(new Response(targets)),
      get: testing.fn().mockResolvedValue({data: targets, meta: {filter: {}}}),
    },
    schedules: {
      getAll: testing.fn().mockResolvedValue(new Response(schedules)),
      get: testing
        .fn()
        .mockResolvedValue({data: schedules, meta: {filter: {}}}),
    },
    scanconfigs: {
      getAll: testing.fn().mockResolvedValue(new Response(scanConfigs)),
      get: testing
        .fn()
        .mockResolvedValue({data: scanConfigs, meta: {filter: {}}}),
    },
    scanners: {
      getAll: testing.fn().mockResolvedValue(new Response(scanners)),
      get: testing.fn().mockResolvedValue({data: scanners, meta: {filter: {}}}),
    },
    credentials: {
      getAll: testing.fn().mockResolvedValue(new Response(credentials)),
      get: testing
        .fn()
        .mockResolvedValue({data: credentials, meta: {filter: {}}}),
    },
    tags: {
      getAll: testing.fn().mockResolvedValue(new Response(tags)),
      get: testing.fn().mockResolvedValue({data: tags, meta: {filter: {}}}),
    },
    task: {
      create: testing
        .fn()
        .mockResolvedValue(createActionResultResponse({id: 'new-id'})),
      save: testing
        .fn()
        .mockResolvedValue(createActionResultResponse({id: 'saved-id'})),
      clone: testing
        .fn()
        .mockResolvedValue(createActionResultResponse({id: 'cloned-id'})),
      export: testing.fn().mockResolvedValue(new Response('some-data')),
      start: testing.fn().mockResolvedValue(new Response({})),
      stop: testing.fn().mockResolvedValue(new Response({})),
      resume: testing.fn().mockResolvedValue(new Response({})),
      delete: testing.fn().mockResolvedValue(new Response({})),
    },
  };
};

describe('TaskComponent tests', () => {
  test('should render', async () => {
    const gmp = createGmp();
    const {render} = rendererWith({gmp});

    render(
      <TaskComponent>{() => <Button data-testid="button" />}</TaskComponent>,
    );

    expect(screen.getByTestId('button')).toBeInTheDocument();
  });

  test('should refresh after an indeterminate native task start', async () => {
    const error = Object.assign(
      new Error('verify task state before retrying'),
      {
        code: 'mutation_outcome_indeterminate',
      },
    );
    const gmp = createGmp();
    gmp.task.start.mockRejectedValue(error);
    const onStarted = testing.fn();
    const onStartError = testing.fn();
    const task = Task.fromElement({_id: 'task-id', name: 'Task'});
    const {render} = rendererWith({gmp});

    render(
      <TaskComponent onStarted={onStarted} onStartError={onStartError}>
        {({start}) => (
          <Button data-testid="start-task" onClick={() => start(task)} />
        )}
      </TaskComponent>,
    );

    fireEvent.click(screen.getByTestId('start-task'));
    await wait();

    expect(onStarted).toHaveBeenCalledTimes(1);
    expect(onStartError).toHaveBeenCalledWith(error);
  });

  test('should open correct dialog on edit for standard task', async () => {
    const gmp = createGmp();
    const {render} = rendererWith({gmp, capabilities: true});

    const standardTask = Task.fromElement({
      _id: 'standard-task-id',
      name: 'Standard Task',
      target: {
        _id: 'target-id',
        name: 'Standard Target',
      },
    });

    render(
      <TaskComponent>
        {({edit}) => (
          <Button
            data-testid="edit-standard-task"
            onClick={() => edit(standardTask)}
          />
        )}
      </TaskComponent>,
    );

    const button = screen.getByTestId('edit-standard-task');
    fireEvent.click(button);

    await wait();

    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByTestId('dialog-test-id')).toBeInTheDocument();
    expect(screen.getByText(/Edit Task/i)).toBeInTheDocument();
  });

  test('should open standard task dialog for new task creation', async () => {
    const gmp = createGmp();
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TaskComponent>
        {({create}) => (
          <Button data-testid="create-task" onClick={() => create()} />
        )}
      </TaskComponent>,
    );

    const button = screen.getByTestId('create-task');
    fireEvent.click(button);

    await wait();

    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByTestId('dialog-test-id')).toBeInTheDocument();
    expect(screen.getByText(/New Task/i)).toBeInTheDocument();
  });

  test('should detect metadata-only standard task edits', () => {
    const standardTask = Task.fromElement({
      _id: 'standard-task-id',
      name: 'Standard Task',
      comment: 'Old comment',
      target: {_id: 'target-id', name: 'Standard Target'},
      config: {_id: 'config-id', name: 'Full and fast'},
      scanner: {_id: 'scanner-id', name: 'OpenVAS', type: '2'},
      schedule: {_id: 'schedule-id', name: 'Daily'},
      schedule_periods: 3,
      alert: [{_id: 'alert-id', name: 'Alert'}],
      preferences: {
        preference: [
          {scanner_name: 'assets_apply_overrides', value: '1'},
          {scanner_name: 'assets_min_qod', value: '70'},
          {scanner_name: 'auto_delete_data', value: '5'},
          {scanner_name: 'max_checks', value: '4'},
          {scanner_name: 'max_hosts', value: '2'},
        ],
      },
    });

    expect(
      isTaskMetadataOnlyDialogSave({
        alert_ids: ['alert-id'],
        apply_overrides: 0,
        comment: 'New comment',
        config_id: 'config-id',
        max_checks: 4,
        max_hosts: 2,
        min_qod: 70,
        name: 'Renamed Task',
        scanner_id: 'scanner-id',
        scanner_type: '2',
        schedule_id: 'schedule-id',
        schedule_periods: 3,
        target_id: 'target-id',
        task: standardTask,
      }),
    ).toEqual(true);
  });

  test('should reject operational standard task edits as metadata-only', () => {
    const standardTask = Task.fromElement({
      _id: 'standard-task-id',
      name: 'Standard Task',
      target: {_id: 'target-id', name: 'Standard Target'},
      config: {_id: 'config-id', name: 'Full and fast'},
      scanner: {_id: 'scanner-id', name: 'OpenVAS', type: '2'},
      schedule_periods: 0,
      preferences: {
        preference: [
          {scanner_name: 'assets_apply_overrides', value: '1'},
          {scanner_name: 'assets_min_qod', value: '70'},
          {scanner_name: 'auto_delete_data', value: '5'},
          {scanner_name: 'max_checks', value: '4'},
          {scanner_name: 'max_hosts', value: '2'},
        ],
      },
    });

    expect(
      isTaskMetadataOnlyDialogSave({
        alert_ids: [],
        apply_overrides: 0,
        comment: 'New comment',
        config_id: 'different-config-id',
        max_checks: 4,
        max_hosts: 2,
        min_qod: 70,
        name: 'Renamed Task',
        scanner_id: 'scanner-id',
        scanner_type: '2',
        schedule_periods: 0,
        target_id: 'target-id',
        task: standardTask,
      }),
    ).toEqual(false);
  });
});

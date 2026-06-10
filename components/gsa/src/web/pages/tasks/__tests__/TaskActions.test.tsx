/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {rendererWithTableRow, fireEvent, screen} from 'web/testing';
import Capabilities from 'gmp/capabilities/capabilities';
import Task, {TASK_STATUS} from 'gmp/models/task';
import {createSession} from 'gmp/testing';
import TaskActions from 'web/pages/tasks/TaskActions';

const wrongCaps = new Capabilities(['get_tasks']);

const createGmp = () => ({
  session: createSession(),
});

describe('TaskActions tests', () => {
  test('should render', () => {
    const task = Task.fromElement({
      status: TASK_STATUS.new,
      alterable: 0,
      permissions: {permission: [{name: 'everything'}]},
      target: {_id: 'id', name: 'target'},
    });

    const handleTaskClone = testing.fn();
    const handleTaskDelete = testing.fn();
    const handleTaskDownload = testing.fn();
    const handleTaskEdit = testing.fn();
    const handleTaskStart = testing.fn();
    const handleTaskStop = testing.fn();

    const {render} = rendererWithTableRow({
      capabilities: true,
      gmp: createGmp(),
    });
    const {element} = render(
      <TaskActions
        entity={task}
        links={true}
        onTaskCloneClick={handleTaskClone}
        onTaskDeleteClick={handleTaskDelete}
        onTaskDownloadClick={handleTaskDownload}
        onTaskEditClick={handleTaskEdit}
        onTaskStartClick={handleTaskStart}
        onTaskStopClick={handleTaskStop}
      />,
    );

    expect(element).toBeInTheDocument();
  });

  test('should call click handlers', () => {
    const task = Task.fromElement({
      status: TASK_STATUS.done,
      alterable: 0,
      last_report: {report: {_id: 'id'}},
      permissions: {permission: [{name: 'everything'}]},
      target: {_id: 'id', name: 'target'},
    });

    const handleTaskClone = testing.fn();
    const handleTaskDelete = testing.fn();
    const handleTaskDownload = testing.fn();
    const handleTaskEdit = testing.fn();
    const handleTaskStart = testing.fn();
    const handleTaskStop = testing.fn();

    const {render} = rendererWithTableRow({
      capabilities: true,
      gmp: createGmp(),
    });
    render(
      <TaskActions
        entity={task}
        links={true}
        onTaskCloneClick={handleTaskClone}
        onTaskDeleteClick={handleTaskDelete}
        onTaskDownloadClick={handleTaskDownload}
        onTaskEditClick={handleTaskEdit}
        onTaskStartClick={handleTaskStart}
        onTaskStopClick={handleTaskStop}
      />,
    );

    const startIcon = screen.getByTestId('start-icon');
    expect(startIcon).toHaveAttribute('title', 'Start');
    fireEvent.click(startIcon);
    expect(handleTaskStart).toHaveBeenCalledWith(task);


    const deleteIcon = screen.getByTestId('trashcan-icon');
    expect(deleteIcon).toHaveAttribute('title', 'Move Task to trashcan');
    fireEvent.click(deleteIcon);
    expect(handleTaskDelete).toHaveBeenCalledWith(task);

    const editIcon = screen.getByTestId('edit-icon');
    expect(editIcon).toHaveAttribute('title', 'Edit Task');
    fireEvent.click(editIcon);
    expect(handleTaskEdit).toHaveBeenCalledWith(task);

    const cloneIcon = screen.getByTestId('clone-icon');
    expect(cloneIcon).toHaveAttribute('title', 'Clone Task');
    fireEvent.click(cloneIcon);
    expect(handleTaskClone).toHaveBeenCalledWith(task);

    const exportIcon = screen.getByTestId('export-icon');
    expect(exportIcon).toHaveAttribute('title', 'Export Task');
    fireEvent.click(exportIcon);
    expect(handleTaskDownload).toHaveBeenCalledWith(task);
  });

  test('should not call click handlers without permissions', () => {
    const task = Task.fromElement({
      status: TASK_STATUS.done,
      alterable: 0,
      last_report: {report: {_id: 'id'}},
      permissions: {permission: [{name: 'get_tasks'}]},
      target: {_id: 'id', name: 'target'},
    });

    const handleTaskClone = testing.fn();
    const handleTaskDelete = testing.fn();
    const handleTaskDownload = testing.fn();
    const handleTaskEdit = testing.fn();
    const handleTaskStart = testing.fn();
    const handleTaskStop = testing.fn();

    const {render} = rendererWithTableRow({
      capabilities: wrongCaps,
      gmp: createGmp(),
    });
    render(
      <TaskActions
        entity={task}
        links={true}
        onTaskCloneClick={handleTaskClone}
        onTaskDeleteClick={handleTaskDelete}
        onTaskDownloadClick={handleTaskDownload}
        onTaskEditClick={handleTaskEdit}
        onTaskStartClick={handleTaskStart}
        onTaskStopClick={handleTaskStop}
      />,
    );

    const startIcon = screen.getByTestId('start-icon');
    expect(startIcon).toHaveAttribute(
      'title',
      'Start task command unavailable',
    );
    fireEvent.click(startIcon);
    expect(handleTaskStart).not.toHaveBeenCalled();


    const deleteIcon = screen.getByTestId('trashcan-icon');
    expect(deleteIcon).toHaveAttribute(
      'title',
      'Move Task to trashcan command unavailable',
    );
    fireEvent.click(deleteIcon);
    expect(handleTaskDelete).not.toHaveBeenCalled();

    const editIcon = screen.getByTestId('edit-icon');
    expect(editIcon).toHaveAttribute('title', 'Edit Task command unavailable');
    fireEvent.click(editIcon);
    expect(handleTaskEdit).not.toHaveBeenCalled();

    const cloneIcon = screen.getByTestId('clone-icon');
    expect(cloneIcon).toHaveAttribute(
      'title',
      'Clone Task command unavailable',
    );
    fireEvent.click(cloneIcon);
    expect(handleTaskClone).not.toHaveBeenCalled();

    const exportIcon = screen.getByTestId('export-icon');
    expect(exportIcon).toHaveAttribute('title', 'Export Task');
    fireEvent.click(exportIcon);
    expect(handleTaskDownload).toHaveBeenCalledWith(task);
  });

  test('should not call click handlers for stopped task without permissions', () => {
    const task = Task.fromElement({
      status: TASK_STATUS.stopped,
      alterable: 0,
      last_report: {report: {_id: 'id'}},
      permissions: {permission: [{name: 'get_tasks'}]},
      target: {_id: 'id', name: 'target'},
    });

    const handleTaskClone = testing.fn();
    const handleTaskDelete = testing.fn();
    const handleTaskDownload = testing.fn();
    const handleTaskEdit = testing.fn();
    const handleTaskStart = testing.fn();
    const handleTaskStop = testing.fn();

    const {render} = rendererWithTableRow({
      capabilities: wrongCaps,
      gmp: createGmp(),
    });
    render(
      <TaskActions
        entity={task}
        links={true}
        onTaskCloneClick={handleTaskClone}
        onTaskDeleteClick={handleTaskDelete}
        onTaskDownloadClick={handleTaskDownload}
        onTaskEditClick={handleTaskEdit}
        onTaskStartClick={handleTaskStart}
        onTaskStopClick={handleTaskStop}
      />,
    );

    const startIcon = screen.getByTestId('start-icon');
    expect(startIcon).toHaveAttribute(
      'title',
      'Start task command unavailable',
    );
    fireEvent.click(startIcon);
    expect(handleTaskStart).not.toHaveBeenCalled();


    const deleteIcon = screen.getByTestId('trashcan-icon');
    expect(deleteIcon).toHaveAttribute(
      'title',
      'Move Task to trashcan command unavailable',
    );
    fireEvent.click(deleteIcon);
    expect(handleTaskDelete).not.toHaveBeenCalled();

    const editIcon = screen.getByTestId('edit-icon');
    expect(editIcon).toHaveAttribute('title', 'Edit Task command unavailable');
    fireEvent.click(editIcon);
    expect(handleTaskEdit).not.toHaveBeenCalled();

    const cloneIcon = screen.getByTestId('clone-icon');
    expect(cloneIcon).toHaveAttribute(
      'title',
      'Clone Task command unavailable',
    );
    fireEvent.click(cloneIcon);
    expect(handleTaskClone).not.toHaveBeenCalled();

    const exportIcon = screen.getByTestId('export-icon');
    expect(exportIcon).toHaveAttribute('title', 'Export Task');
    fireEvent.click(exportIcon);
    expect(handleTaskDownload).toHaveBeenCalledWith(task);
  });

  test('should not call click handlers for running task without permissions', () => {
    const task = Task.fromElement({
      status: TASK_STATUS.running,
      alterable: 0,
      last_report: {report: {_id: 'id'}},
      permissions: {permission: [{name: 'get_tasks'}]},
      target: {_id: 'id', name: 'target'},
    });

    const handleTaskClone = testing.fn();
    const handleTaskDelete = testing.fn();
    const handleTaskDownload = testing.fn();
    const handleTaskEdit = testing.fn();
    const handleTaskStart = testing.fn();
    const handleTaskStop = testing.fn();

    const {render} = rendererWithTableRow({
      capabilities: wrongCaps,
      gmp: createGmp(),
    });
    render(
      <TaskActions
        entity={task}
        links={true}
        onTaskCloneClick={handleTaskClone}
        onTaskDeleteClick={handleTaskDelete}
        onTaskDownloadClick={handleTaskDownload}
        onTaskEditClick={handleTaskEdit}
        onTaskStartClick={handleTaskStart}
        onTaskStopClick={handleTaskStop}
      />,
    );

    const stopIcon = screen.getByTestId('stop-icon');
    expect(stopIcon).toHaveAttribute('title', 'Stop task command unavailable');
    fireEvent.click(stopIcon);
    expect(handleTaskStart).not.toHaveBeenCalled();


    const deleteIcon = screen.getByTestId('trashcan-icon');
    expect(deleteIcon).toHaveAttribute(
      'title',
      'Move Task to trashcan command unavailable',
    );
    fireEvent.click(deleteIcon);
    expect(handleTaskDelete).not.toHaveBeenCalled();

    const editIcon = screen.getByTestId('edit-icon');
    expect(editIcon).toHaveAttribute('title', 'Edit Task command unavailable');
    fireEvent.click(editIcon);
    expect(handleTaskEdit).not.toHaveBeenCalled();

    const cloneIcon = screen.getByTestId('clone-icon');
    expect(cloneIcon).toHaveAttribute(
      'title',
      'Clone Task command unavailable',
    );
    fireEvent.click(cloneIcon);
    expect(handleTaskClone).not.toHaveBeenCalled();

    const exportIcon = screen.getByTestId('export-icon');
    expect(exportIcon).toHaveAttribute('title', 'Export Task');
    fireEvent.click(exportIcon);
    expect(handleTaskDownload).toHaveBeenCalledWith(task);
  });

  test('should call click handlers for running task', () => {
    const task = Task.fromElement({
      status: TASK_STATUS.running,
      alterable: 0,
      in_use: 1,
      permissions: {permission: [{name: 'everything'}]},
      target: {_id: 'id', name: 'target'},
    });

    const handleTaskClone = testing.fn();
    const handleTaskDelete = testing.fn();
    const handleTaskDownload = testing.fn();
    const handleTaskEdit = testing.fn();
    const handleTaskStart = testing.fn();
    const handleTaskStop = testing.fn();

    const {render} = rendererWithTableRow({
      capabilities: true,
      gmp: createGmp(),
    });
    render(
      <TaskActions
        entity={task}
        links={true}
        onTaskCloneClick={handleTaskClone}
        onTaskDeleteClick={handleTaskDelete}
        onTaskDownloadClick={handleTaskDownload}
        onTaskEditClick={handleTaskEdit}
        onTaskStartClick={handleTaskStart}
        onTaskStopClick={handleTaskStop}
      />,
    );

    const stopIcon = screen.getByTestId('stop-icon');
    expect(stopIcon).toHaveAttribute('title', 'Stop');
    fireEvent.click(stopIcon);
    expect(handleTaskStop).toHaveBeenCalledWith(task);


    const deleteIcon = screen.getByTestId('trashcan-icon');
    expect(deleteIcon).toHaveAttribute('title', 'Task is still in use');
    fireEvent.click(deleteIcon);
    expect(handleTaskDelete).not.toHaveBeenCalled();

    const editIcon = screen.getByTestId('edit-icon');
    expect(editIcon).toHaveAttribute('title', 'Edit Task');
    fireEvent.click(editIcon);
    expect(handleTaskEdit).toHaveBeenCalledWith(task);

    const cloneIcon = screen.getByTestId('clone-icon');
    expect(cloneIcon).toHaveAttribute('title', 'Clone Task');
    fireEvent.click(cloneIcon);
    expect(handleTaskClone).toHaveBeenCalledWith(task);

    const exportIcon = screen.getByTestId('export-icon');
    expect(exportIcon).toHaveAttribute('title', 'Export Task');
    fireEvent.click(exportIcon);
    expect(handleTaskDownload).toHaveBeenCalledWith(task);
  });

  test('should call click handlers for stopped task', () => {
    const task = Task.fromElement({
      status: TASK_STATUS.stopped,
      alterable: 0,
      last_report: {report: {_id: 'id'}},
      permissions: {permission: [{name: 'everything'}]},
      target: {_id: 'id', name: 'target'},
    });

    const handleTaskClone = testing.fn();
    const handleTaskDelete = testing.fn();
    const handleTaskDownload = testing.fn();
    const handleTaskEdit = testing.fn();
    const handleTaskStart = testing.fn();
    const handleTaskStop = testing.fn();

    const {render} = rendererWithTableRow({
      capabilities: true,
      gmp: createGmp(),
    });
    render(
      <TaskActions
        entity={task}
        links={true}
        onTaskCloneClick={handleTaskClone}
        onTaskDeleteClick={handleTaskDelete}
        onTaskDownloadClick={handleTaskDownload}
        onTaskEditClick={handleTaskEdit}
        onTaskStartClick={handleTaskStart}
        onTaskStopClick={handleTaskStop}
      />,
    );

    const startIcon = screen.getByTestId('start-icon');
    expect(startIcon).toHaveAttribute('title', 'Start');
    fireEvent.click(startIcon);
    expect(handleTaskStart).toHaveBeenCalledWith(task);


    const deleteIcon = screen.getByTestId('trashcan-icon');
    expect(deleteIcon).toHaveAttribute('title', 'Move Task to trashcan');
    fireEvent.click(deleteIcon);
    expect(handleTaskDelete).toHaveBeenCalledWith(task);

    const editIcon = screen.getByTestId('edit-icon');
    expect(editIcon).toHaveAttribute('title', 'Edit Task');
    fireEvent.click(editIcon);
    expect(handleTaskEdit).toHaveBeenCalledWith(task);

    const cloneIcon = screen.getByTestId('clone-icon');
    expect(cloneIcon).toHaveAttribute('title', 'Clone Task');
    fireEvent.click(cloneIcon);
    expect(handleTaskClone).toHaveBeenCalledWith(task);

    const exportIcon = screen.getByTestId('export-icon');
    expect(exportIcon).toHaveAttribute('title', 'Export Task');
    fireEvent.click(exportIcon);
    expect(handleTaskDownload).toHaveBeenCalledWith(task);
  });

  test('should render schedule icon if task is scheduled', () => {
    const task = Task.fromElement({
      status: TASK_STATUS.stopped,
      alterable: 0,
      last_report: {report: {_id: 'id'}},
      permissions: {permission: [{name: 'everything'}]},
      target: {_id: 'id', name: 'target'},
      schedule: {
        _id: 'schedule1',
        name: 'schedule1',
        permissions: {permission: [{name: 'everything'}]},
      },
    });

    const handleTaskClone = testing.fn();
    const handleTaskDelete = testing.fn();
    const handleTaskDownload = testing.fn();
    const handleTaskEdit = testing.fn();
    const handleTaskStart = testing.fn();
    const handleTaskStop = testing.fn();

    const {render} = rendererWithTableRow({
      capabilities: true,
      gmp: createGmp(),
      router: true,
    });
    render(
      <TaskActions
        entity={task}
        links={true}
        onTaskCloneClick={handleTaskClone}
        onTaskDeleteClick={handleTaskDelete}
        onTaskDownloadClick={handleTaskDownload}
        onTaskEditClick={handleTaskEdit}
        onTaskStartClick={handleTaskStart}
        onTaskStopClick={handleTaskStop}
      />,
    );

    const detailsLinks = screen.getAllByTestId('details-link');
    fireEvent.click(detailsLinks[0]);
    expect(detailsLinks[0]).toHaveAttribute(
      'title',
      'View Details of Schedule schedule1 (Next due: over)',
    );

    const startIcon = screen.getByTestId('start-icon');
    expect(startIcon).toHaveAttribute('title', 'Start');
    fireEvent.click(startIcon);
    expect(handleTaskStart).toHaveBeenCalledWith(task);


    const deleteIcon = screen.getByTestId('trashcan-icon');
    expect(deleteIcon).toHaveAttribute('title', 'Move Task to trashcan');
    fireEvent.click(deleteIcon);
    expect(handleTaskDelete).toHaveBeenCalledWith(task);

    const editIcon = screen.getByTestId('edit-icon');
    expect(editIcon).toHaveAttribute('title', 'Edit Task');
    fireEvent.click(editIcon);
    expect(handleTaskEdit).toHaveBeenCalledWith(task);

    const cloneIcon = screen.getByTestId('clone-icon');
    expect(cloneIcon).toHaveAttribute('title', 'Clone Task');
    fireEvent.click(cloneIcon);
    expect(handleTaskClone).toHaveBeenCalledWith(task);

    const exportIcon = screen.getByTestId('export-icon');
    expect(exportIcon).toHaveAttribute('title', 'Export Task');
    fireEvent.click(exportIcon);
    expect(handleTaskDownload).toHaveBeenCalledWith(task);
  });

});

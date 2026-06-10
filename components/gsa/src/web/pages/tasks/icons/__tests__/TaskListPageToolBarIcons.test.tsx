/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {screen, rendererWith, fireEvent} from 'web/testing';
import Capabilities from 'gmp/capabilities/capabilities';
import TaskToolBarIcons from 'web/pages/tasks/icons/TaskListPageToolBarIcons';

const manualUrl = 'test/';

describe('TaskListPageToolBarIcons test', () => {
  test('should render', () => {
    const handleTaskCreateClick = testing.fn();

    const gmp = {
      settings: {manualUrl},
    };

    const {render} = rendererWith({
      gmp,
      capabilities: true,
      router: true,
    });

    render(
      <TaskToolBarIcons
        onTaskCreateClick={handleTaskCreateClick}
      />,
    );
    expect(screen.getByTestId('help-icon')).toHaveAttribute(
      'title',
      'Help: Tasks',
    );
    expect(screen.getByTestId('manual-link')).toHaveAttribute(
      'href',
      'test/en/scanning.html#managing-tasks',
    );
  });

  test('should call click handlers', async () => {
    const handleTaskCreateClick = testing.fn();

    const gmp = {
      settings: {manualUrl},
    };

    const {render} = rendererWith({
      gmp,
      capabilities: true,
      router: true,
    });

    render(
      <TaskToolBarIcons
        onTaskCreateClick={handleTaskCreateClick}
      />,
    );

    const newTaskButton = screen.getByTitle('New Task');
    fireEvent.click(newTaskButton);
    expect(handleTaskCreateClick).toHaveBeenCalled();
  });
  test('should not show icons if user does not have the right permissions', () => {
    const handleTaskCreateClick = testing.fn();

    const gmp = {
      settings: {manualUrl},
    };

    const {render} = rendererWith({
      gmp,
      capabilities: new Capabilities(),
      router: true,
    });
    render(
      <TaskToolBarIcons
        onTaskCreateClick={handleTaskCreateClick}
      />,
    );

    const newTaskButton = screen.queryByTestId('new-task');
    expect(newTaskButton).toBeNull();
  });
});

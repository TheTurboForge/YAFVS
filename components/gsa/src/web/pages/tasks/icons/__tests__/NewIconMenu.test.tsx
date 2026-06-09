/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {screen, rendererWith, fireEvent} from 'web/testing';
import Capabilities from 'gmp/capabilities/capabilities';
import NewIconMenu from 'web/pages/tasks/icons/NewIconMenu';

describe('NewIconMenu tests', () => {
  test('should render', async () => {
    const {render} = rendererWith({capabilities: true});
    render(<NewIconMenu />);

    const button = screen.getByTitle('New Task Menu');
    expect(button).not.toBeNull();
    fireEvent.click(button);

    await screen.findByTestId('new-task-menu');
    expect(screen.getByTestId('new-task-menu')).toBeInTheDocument();
    expect(screen.getByTestId('new-import-task-menu')).toBeInTheDocument();
  });

  test('should not render when capabilities do not allow creating tasks', () => {
    const {render} = rendererWith({capabilities: new Capabilities()});
    render(<NewIconMenu />);
    expect(screen.queryByTestId('new-task-menu')).not.toBeInTheDocument();
    expect(
      screen.queryByTestId('new-import-task-menu'),
    ).not.toBeInTheDocument();
  });

  test('should call onNewClick when New Task is clicked', async () => {
    const onNewClick = testing.fn();
    const {render} = rendererWith({capabilities: true});
    render(<NewIconMenu onNewClick={onNewClick} />);

    const button = screen.getByTitle('New Task Menu');
    expect(button).not.toBeNull();
    fireEvent.click(button);

    const menuItem = await screen.findByTestId('new-task-menu');
    fireEvent.click(menuItem);
    expect(onNewClick).toHaveBeenCalled();
  });

  test('calls onNewImportTaskClick when New Import Task is clicked', async () => {
    const onNewImportTaskClick = testing.fn();
    const {render} = rendererWith({capabilities: true});
    render(<NewIconMenu onNewImportTaskClick={onNewImportTaskClick} />);

    const button = screen.getByTitle('New Task Menu');
    expect(button).not.toBeNull();
    fireEvent.click(button);

    const menuItem = await screen.findByTestId('new-import-task-menu');
    fireEvent.click(menuItem);
    expect(onNewImportTaskClick).toHaveBeenCalled();
  });

});

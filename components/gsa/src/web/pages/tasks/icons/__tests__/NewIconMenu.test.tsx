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

    const button = screen.getByTitle('New Task');
    expect(button).not.toBeNull();
    expect(screen.getByTestId('new-task')).toBeInTheDocument();
  });

  test('should not render when capabilities do not allow creating tasks', () => {
    const {render} = rendererWith({capabilities: new Capabilities()});
    render(<NewIconMenu />);
    expect(screen.queryByTestId('new-task')).not.toBeInTheDocument();
  });

  test('should call onNewClick when New Task is clicked', async () => {
    const onNewClick = testing.fn();
    const {render} = rendererWith({capabilities: true});
    render(<NewIconMenu onNewClick={onNewClick} />);

    const button = screen.getByTitle('New Task');
    expect(button).not.toBeNull();
    fireEvent.click(button);

    expect(onNewClick).toHaveBeenCalled();
  });
});

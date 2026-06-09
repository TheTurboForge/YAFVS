/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {NewIcon} from 'web/components/icon';
import IconMenu from 'web/components/menu/IconMenu';
import MenuEntry from 'web/components/menu/MenuEntry';
import useCapabilities from 'web/hooks/useCapabilities';
import useTranslation from 'web/hooks/useTranslation';

interface NewIconMenuProps {
  onNewClick?: () => void;
  onNewImportTaskClick?: () => void;
}

const NewIconMenu = ({
  onNewClick,
  onNewImportTaskClick,
}: NewIconMenuProps) => {
  const [_] = useTranslation();
  const capabilities = useCapabilities();
  if (capabilities.mayCreate('task')) {
    return (
      <IconMenu icon={<NewIcon />} title={_('New Task Menu')}>
        <MenuEntry
          data-testid="new-task-menu"
          title={_('New Task')}
          onClick={onNewClick}
        />
        <MenuEntry
          data-testid="new-import-task-menu"
          title={_('New Import Task')}
          onClick={onNewImportTaskClick}
        />
      </IconMenu>
    );
  }
  return null;
};

export default NewIconMenu;

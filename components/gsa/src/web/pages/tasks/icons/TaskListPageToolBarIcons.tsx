/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import ManualIcon from 'web/components/icon/ManualIcon';
import IconDivider from 'web/components/layout/IconDivider';
import useTranslation from 'web/hooks/useTranslation';
import NewIconMenu from 'web/pages/tasks/icons/NewIconMenu';

interface TaskToolBarIconsProps {
  onTaskCreateClick?: () => void;
}

const TaskToolBarIcons = ({onTaskCreateClick}: TaskToolBarIconsProps) => {
  const [_] = useTranslation();
  return (
    <IconDivider>
      <ManualIcon
        anchor="managing-tasks"
        page="scanning"
        title={_('Help: Tasks')}
      />
      <NewIconMenu onNewClick={onTaskCreateClick} />
    </IconDivider>
  );
};

export default TaskToolBarIcons;

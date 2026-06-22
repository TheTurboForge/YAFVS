/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useSelector} from 'react-redux';
import type Task from 'gmp/models/task';
import {StartIcon} from 'web/components/icon';
import useTranslation from 'web/hooks/useTranslation';
import TaskStartIconBase from 'web/pages/tasks/icons/TaskStartIcon';

interface TaskIconWithSyncProps {
  task: Task;
  onClick?: (task: Task) => void | Promise<void>;
}

const TaskIconWithSync = (props: TaskIconWithSyncProps) => {
  const [_] = useTranslation();

  const feedSyncingStatus = useSelector<
    {feedStatus: {isSyncing: boolean}},
    {isSyncing: boolean}
  >(state => state.feedStatus);

  if (feedSyncingStatus.isSyncing) {
    return (
      <StartIcon
        active={false}
        title={_('Feed is currently syncing. Please try again later.')}
      />
    );
  }

  return <TaskStartIconBase {...props} />;
};

export default TaskIconWithSync;

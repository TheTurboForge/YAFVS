/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Task from 'gmp/models/task';
import {StopIcon} from 'web/components/icon';
import {type ExtendedIconSize} from 'web/components/icon/DynamicIcon';
import useCapabilities from 'web/hooks/useCapabilities';
import useTranslation from 'web/hooks/useTranslation';

interface TaskStopIconProps<TTask extends Task> {
  size?: ExtendedIconSize;
  task: TTask;
  onClick?: (task: TTask) => void | Promise<void>;
}

const TaskStopIcon = <TTask extends Task>({
  size,
  task,
  onClick,
}: TaskStopIconProps<TTask>) => {
  const capabilities = useCapabilities();
  const [_] = useTranslation();
  const type = _('task');

  if (task.isRunning() || task.isQueued()) {
    if (
      !capabilities.mayOp('stop_task') ||
      !task.userCapabilities.mayOp('stop_task')
    ) {
      return (
        <StopIcon
          active={false}
          title={_('Stop {{type}} command unavailable', {type})}
        />
      );
    }
    return (
      <StopIcon
        size={size}
        title={_('Stop')}
        value={task}
        onClick={onClick as (task?: TTask) => void | Promise<void>}
      />
    );
  }
  return null;
};

export default TaskStopIcon;

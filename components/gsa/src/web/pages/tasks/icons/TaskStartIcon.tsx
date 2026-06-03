/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Task from 'gmp/models/task';
import {isDefined} from 'gmp/utils/identity';
import {capitalizeFirstLetter} from 'gmp/utils/string';
import {StartIcon} from 'web/components/icon';
import useCapabilities from 'web/hooks/useCapabilities';
import useTranslation from 'web/hooks/useTranslation';

interface TaskStartIconProps<TTask extends Task> {
  task: TTask;
  onClick?: (task: TTask) => void | Promise<void>;
}

const TaskStartIcon = <TTask extends Task>({
  task,
  onClick,
}: TaskStartIconProps<TTask>) => {
  const [_] = useTranslation();
  const type = _('task');

  const capabilities = useCapabilities();

  if (task.isRunning() || task.isImport()) {
    return null;
  }

  if (
    !capabilities.mayOp('start_task') ||
    !task.userCapabilities.mayOp('start_task')
  ) {
    return (
      <StartIcon
        active={false}
        title={_('Start {{type}} command unavailable', {type})}
      />
    );
  }

  if (
    isDefined(task.schedule?.event?.duration) &&
    task.schedule.event.event.duration.toSeconds() > 0
  ) {
    return (
      <StartIcon
        active={false}
        title={_(
          '{{type}} cannot be started manually' +
            ' because the assigned schedule has a duration limit',
          {
            type: capitalizeFirstLetter(type),
          },
        )}
      />
    );
  }

  if (!task.isActive()) {
    return (
      <StartIcon
        title={_('Start')}
        value={task}
        onClick={onClick as (tasks?: TTask) => void | Promise<void>}
      />
    );
  }
  return (
    <StartIcon
      active={false}
      title={_('{{type}} is already active', {
        type: capitalizeFirstLetter(type),
      })}
    />
  );
};

export default TaskStartIcon;

/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Task from 'gmp/models/task';
import {isDefined} from 'gmp/utils/identity';
import {capitalizeFirstLetter} from 'gmp/utils/string';
import {ResumeIcon} from 'web/components/icon';
import useCapabilities from 'web/hooks/useCapabilities';
import useTranslation from 'web/hooks/useTranslation';

interface TaskResumeIconProps<TTask extends Task> {
  task: TTask;
  onClick?: (task: TTask) => void | Promise<void>;
}

const TaskResumeIcon = <TTask extends Task>({
  task,
  onClick,
}: TaskResumeIconProps<TTask>) => {
  const [_] = useTranslation();
  const type = _('task');
  const capabilities = useCapabilities();

  if (task.isQueued()) {
    return null;
  }

  if (task.isImport()) {
    return (
      <ResumeIcon
        active={false}
        title={_('{{type}} is for import only', {
          type: capitalizeFirstLetter(type),
        })}
      />
    );
  }

  if (isDefined(task.schedule)) {
    return (
      <ResumeIcon
        active={false}
        title={_('{{type}} is scheduled', {
          type: capitalizeFirstLetter(type),
        })}
      />
    );
  }

  if (task.isStopped() || task.isInterrupted()) {
    if (
      capabilities.mayOp('start_task') &&
      task.userCapabilities.mayOp('start_task')
    ) {
      return (
        <ResumeIcon
          title={_('Resume')}
          value={task}
          onClick={onClick as (task?: TTask) => void | Promise<void>}
        />
      );
    }
    return (
      <ResumeIcon
        active={false}
        title={_('Resume {{type}} command unavailable', {type})}
      />
    );
  }

  return (
    <ResumeIcon
      active={false}
      title={_('{{type}} is not stopped', {
        type: capitalizeFirstLetter(type),
      })}
    />
  );
};

export default TaskResumeIcon;

/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {TASKS_FILTER_FILTER} from 'gmp/models/filter';
import type Task from 'gmp/models/task';
import {TaskIcon} from 'web/components/icon';
import PageTitle from 'web/components/layout/PageTitle';
import {
  USE_DEFAULT_RELOAD_INTERVAL,
  USE_DEFAULT_RELOAD_INTERVAL_ACTIVE,
} from 'web/components/loading/Reload';
import EntitiesPage from 'web/entities/EntitiesPage';
import withEntitiesContainer, {
  type WithEntitiesContainerComponentProps,
} from 'web/entities/withEntitiesContainer';
import useTranslation from 'web/hooks/useTranslation';
import TaskToolBarIcons from 'web/pages/tasks/icons/TaskListPageToolBarIcons';
import TaskComponent from 'web/pages/tasks/TaskComponent';
import TaskFilterDialog from 'web/pages/tasks/TaskFilterDialog';
import TaskTable from 'web/pages/tasks/TaskTable';
import {
  loadEntities,
  selector as entitiesSelector,
} from 'web/store/entities/tasks';

type TaskListPageProps = WithEntitiesContainerComponentProps<Task>;

interface TaskEntitiesPageProps {
  onTaskCloneClick?: (task: Task) => void;
  onTaskCreateClick?: () => void;
  onTaskDeleteClick?: (task: Task) => void;
  onTaskDownloadClick?: (task: Task) => void;
  onTaskEditClick?: (task: Task) => void;
  onTaskStartClick?: (task: Task) => void;
  onTaskStopClick?: (task: Task) => void;
}

const TaskListPage = ({
  filter,
  onFilterChanged,
  onChanged,
  onDownloaded,
  onError,
  ...props
}: TaskListPageProps) => {
  const [_] = useTranslation();
  return (
    <TaskComponent
      onCloneError={onError}
      onCloned={onChanged}
      onCreated={onChanged}
      onDeleteError={onError}
      onDeleted={onChanged}
      onDownloadError={onError}
      onDownloaded={onDownloaded}
      onSaved={onChanged}
      onStartError={onError}
      onStarted={onChanged}
      onStopError={onError}
      onStopped={onChanged}
    >
      {({
        clone,
        create,
        delete: deleteFunc,
        download,
        edit,
        start,
        stop,
      }) => (
        <>
          <PageTitle title={_('Tasks')} />
          <EntitiesPage<Task, TaskEntitiesPageProps>
            {...props}
            filter={filter}
            filterEditDialog={TaskFilterDialog}
            filtersFilter={TASKS_FILTER_FILTER}
            sectionIcon={<TaskIcon size="large" />}
            table={TaskTable}
            title={_('Tasks')}
            toolBarIcons={TaskToolBarIcons}
            onError={onError}
            onFilterChanged={onFilterChanged}
            onTaskCloneClick={clone}
            onTaskCreateClick={create}
            onTaskDeleteClick={deleteFunc}
            onTaskDownloadClick={download}
            onTaskEditClick={edit}
            onTaskStartClick={start}
            onTaskStopClick={stop}
          />
        </>
      )}
    </TaskComponent>
  );
};

export const taskReloadInterval = ({entities = []}: {entities: Task[]}) =>
  entities.some(task => task.isActive())
    ? USE_DEFAULT_RELOAD_INTERVAL_ACTIVE
    : USE_DEFAULT_RELOAD_INTERVAL;

export default withEntitiesContainer('task', {
  entitiesSelector,
  loadEntities,
  nativeListExportExtension: 'json',
  reloadInterval: taskReloadInterval,
})(TaskListPage);

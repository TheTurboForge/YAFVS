/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {useNavigate} from 'react-router';
import type Gmp from 'gmp/gmp';
import Filter from 'gmp/models/filter';
import type Override from 'gmp/models/override';
import type Task from 'gmp/models/task';
import {isDefined} from 'gmp/utils/identity';
import {TaskIcon} from 'web/components/icon';
import Layout from 'web/components/layout/Layout';
import PageTitle from 'web/components/layout/PageTitle';
import {
  NO_RELOAD,
  USE_DEFAULT_RELOAD_INTERVAL,
  USE_DEFAULT_RELOAD_INTERVAL_ACTIVE,
} from 'web/components/loading/Reload';
import Tab from 'web/components/tab/Tab';
import TabLayout from 'web/components/tab/TabLayout';
import TabList from 'web/components/tab/TabList';
import TabPanel from 'web/components/tab/TabPanel';
import TabPanels from 'web/components/tab/TabPanels';
import Tabs from 'web/components/tab/Tabs';
import TabsContainer from 'web/components/tab/TabsContainer';
import InfoTable from 'web/components/table/InfoTable';
import TableBody from 'web/components/table/TableBody';
import TableCol from 'web/components/table/TableCol';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import EntitiesTab from 'web/entity/EntitiesTab';
import EntityPage from 'web/entity/EntityPage';
import {type OnDownloadedFunc} from 'web/entity/hooks/useEntityDownload';
import {goToDetails, goToList} from 'web/entity/navigation';
import EntityTags from 'web/entity/Tags';
import withEntityContainer from 'web/entity/withEntityContainer';
import useFeatures from 'web/hooks/useFeatures';
import useTranslation from 'web/hooks/useTranslation';
import TaskDetailsPageToolBarIcons from 'web/pages/tasks/icons/TaskDetailsPageToolBarIcons';
import TaskComponent from 'web/pages/tasks/TaskComponent';
import TaskDetails from 'web/pages/tasks/TaskDetails';
import TaskStatus from 'web/pages/tasks/TaskStatus';
import {
  selector as overridesSelector,
  loadEntities as loadOverrides,
} from 'web/store/entities/overrides';
import {
  selector as taskSelector,
  loadEntity as loadTask,
} from 'web/store/entities/tasks';
import {renderYesNo} from 'web/utils/Render';

interface DetailsProps {
  entity: Task;
  links?: boolean;
}

interface TaskDetailsPageProps {
  entity: Task;
  overrides?: Override[];
  isLoading?: boolean;
  onChanged?: () => void;
  onDownloaded?: OnDownloadedFunc;
  onError?: (error: unknown) => void;
}

const Details = ({entity, links}: DetailsProps) => {
  const [_] = useTranslation();
  const features = useFeatures();

  const isCredentialStore = features.featureEnabled('ENABLE_CREDENTIAL_STORES');

  return (
    <Layout flex="column">
      <InfoTable>
        <colgroup>
          <TableCol width="10%" />
          <TableCol width="90%" />
        </colgroup>
        <TableBody>
          <TableRow>
            <TableData>{_('Name')}</TableData>
            <TableData>{entity.name}</TableData>
          </TableRow>

          <TableRow>
            <TableData>{_('Comment')}</TableData>
            <TableData>{entity.comment}</TableData>
          </TableRow>

          <TableRow>
            <TableData>{_('Alterable')}</TableData>
            <TableData>{renderYesNo(entity.isAlterable())}</TableData>
          </TableRow>

          <TableRow>
            <TableData>{_('Status')}</TableData>
            <TableData>
              <TaskStatus task={entity} />
            </TableData>
          </TableRow>

          {isCredentialStore && (
            <TableRow>
              <TableData>
                {_('Allow scan when credential store retrieval fails')}
              </TableData>
              <TableData>
                {renderYesNo(entity.csAllowFailedRetrieval)}
              </TableData>
            </TableRow>
          )}
        </TableBody>
      </InfoTable>

      <TaskDetails entity={entity} links={links} />
    </Layout>
  );
};

const TaskDetailsPage = ({
  entity,
  overrides = [],
  isLoading = false,
  onChanged,
  onDownloaded,
  onError,
  ...props
}: TaskDetailsPageProps) => {
  const navigate = useNavigate();
  const [_] = useTranslation();

  return (
    <TaskComponent
      onCloneError={onError}
      onCloned={goToDetails('task', navigate)}
      onCreated={goToDetails('task', navigate)}
      onDeleteError={onError}
      onDeleted={goToList('tasks', navigate)}
      onDownloadError={onError}
      onDownloaded={onDownloaded}
      onImportTaskCreated={goToDetails('task', navigate)}
      onImportTaskSaved={onChanged}
      onReportImported={onChanged}
      onResumeError={onError}
      onResumed={onChanged}
      onSaved={onChanged}
      onStartError={onError}
      onStarted={onChanged}
      onStopError={onError}
      onStopped={onChanged}
    >
      {({
        clone,
        create,
        createImportTask,
        delete: deleteFunc,
        download,
        edit,
        start,
        stop,
        resume,
        reportImport,
      }) => (
        <EntityPage
          {...props}
          entity={entity}
          isLoading={isLoading}
          sectionIcon={<TaskIcon size="large" />}
          title={_('Task')}
          toolBarIcons={
            <TaskDetailsPageToolBarIcons
              entity={entity}
              overridesCount={overrides.length}
              onImportTaskCreateClick={createImportTask}
              onReportImportClick={reportImport}
              onTaskCloneClick={clone}
              onTaskCreateClick={create}
              onTaskDeleteClick={deleteFunc}
              onTaskDownloadClick={download}
              onTaskEditClick={edit}
              onTaskResumeClick={resume}
              onTaskStartClick={start}
              onTaskStopClick={stop}
            />
          }
        >
          {() => {
            return (
              <React.Fragment>
                <PageTitle
                  title={_('Task: {{name}}', {name: entity.name as string})}
                />
                <TabsContainer flex="column" grow="1">
                  <TabLayout align={['start', 'end']} grow="1">
                    <TabList align={['start', 'stretch']}>
                      <Tab>{_('Information')}</Tab>
                      <EntitiesTab entities={entity.userTags}>
                        {_('User Tags')}
                      </EntitiesTab>
                    </TabList>
                  </TabLayout>

                  <Tabs>
                    <TabPanels>
                      <TabPanel>
                        <Details entity={entity} />
                      </TabPanel>
                      <TabPanel>
                        <EntityTags
                          entity={entity}
                          onChanged={onChanged}
                          onError={onError}
                        />
                      </TabPanel>
                    </TabPanels>
                  </Tabs>
                </TabsContainer>
              </React.Fragment>
            );
          }}
        </EntityPage>
      )}
    </TaskComponent>
  );
};


const taskIdFilter = (id: string) => Filter.fromString('task_id=' + id).all();

const mapStateToProps = (rootState: unknown, {id}: {id: string}) => {
  const overridesSel = overridesSelector(rootState);
  return {
    overrides: overridesSel.getEntities(taskIdFilter(id)),
  };
};

const load = (gmp: Gmp) => {
  const loadTaskFunc = loadTask(gmp);
  const loadOverridesFunc = loadOverrides(gmp);
  return (id: string) => dispatch =>
    Promise.all([
      dispatch(loadTaskFunc(id)),
      dispatch(loadOverridesFunc(taskIdFilter(id))),
    ]);
};

export const reloadInterval = ({entity}: {entity: Task}) => {
  if (!isDefined(entity) || entity.isImport()) {
    return NO_RELOAD;
  }
  return entity.isActive()
    ? USE_DEFAULT_RELOAD_INTERVAL_ACTIVE
    : USE_DEFAULT_RELOAD_INTERVAL;
};

export default withEntityContainer('task', {
  load,
  entitySelector: taskSelector,
  mapStateToProps,
  // @ts-expect-error
  reloadInterval,
})(TaskDetailsPage);

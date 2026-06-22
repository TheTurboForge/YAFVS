/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {ScheduleIcon} from 'web/components/icon';
import PageTitle from 'web/components/layout/PageTitle';
import Tab from 'web/components/tab/Tab';
import TabLayout from 'web/components/tab/TabLayout';
import TabList from 'web/components/tab/TabList';
import TabPanel from 'web/components/tab/TabPanel';
import TabPanels from 'web/components/tab/TabPanels';
import Tabs from 'web/components/tab/Tabs';
import TabsContainer from 'web/components/tab/TabsContainer';
import EntitiesTab from 'web/entity/EntitiesTab';
import EntityPage from 'web/entity/EntityPage';
import {goToDetails, goToList} from 'web/entity/navigation';
import EntityTags from 'web/entity/Tags';
import withEntityContainer from 'web/entity/withEntityContainer';
import useTranslation from 'web/hooks/useTranslation';
import ScheduleDetails from 'web/pages/schedules/Details';
import ScheduleComponent from 'web/pages/schedules/ScheduleComponent';
import ScheduleDetailsPageToolBarIcons from 'web/pages/schedules/ScheduleDetailsPageToolBarIcons';
import {selector, loadEntity} from 'web/store/entities/schedules';
import PropTypes from 'web/utils/PropTypes';

const Page = ({
  entity,
  onChanged,
  onDownloaded,
  onError,
  ...props
}) => {
  const [_] = useTranslation();

  return (
    <ScheduleComponent
      onCloneError={onError}
      onCloned={goToDetails('schedule', props)}
      onCreated={goToDetails('schedule', props)}
      onDeleteError={onError}
      onDeleted={goToList('schedules', props)}
      onDownloadError={onError}
      onDownloaded={onDownloaded}
      onSaved={onChanged}
    >
      {({clone, create, delete: delete_func, download, edit, save}) => (
        <EntityPage
          {...props}
          entity={entity}
          sectionIcon={<ScheduleIcon size="large" />}
          title={_('Schedule')}
          toolBarIcons={ScheduleDetailsPageToolBarIcons}
          onScheduleCloneClick={clone}
          onScheduleCreateClick={create}
          onScheduleDeleteClick={delete_func}
          onScheduleDownloadClick={download}
          onScheduleEditClick={edit}
          onScheduleSaveClick={save}
        >
          {() => {
            return (
              <React.Fragment>
                <PageTitle
                  title={_('Schedule: {{name}}', {name: entity.name})}
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
                        <ScheduleDetails entity={entity} />
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
    </ScheduleComponent>
  );
};

Page.propTypes = {
  entity: PropTypes.model,
  onChanged: PropTypes.func.isRequired,
  onDownloaded: PropTypes.func.isRequired,
  onError: PropTypes.func.isRequired,
};

const load = gmp => {
  const loadEntityFunc = loadEntity(gmp);
  return id => dispatch =>
    Promise.all([
      dispatch(loadEntityFunc(id)),
    ]);
};

const mapStateToProps = (rootState, {id}) => {
  return {
  };
};

export default withEntityContainer('schedule', {
  entitySelector: selector,
  load,
  mapStateToProps,
})(Page);

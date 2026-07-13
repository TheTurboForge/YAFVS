/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {AlertIcon} from 'web/components/icon';
import ExportIcon from 'web/components/icon/ExportIcon';
import ListIcon from 'web/components/icon/ListIcon';
import ManualIcon from 'web/components/icon/ManualIcon';
import Divider from 'web/components/layout/Divider';
import IconDivider from 'web/components/layout/IconDivider';
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
import CloneIcon from 'web/entity/icon/CloneIcon';
import CreateIcon from 'web/entity/icon/CreateIcon';
import EditIcon from 'web/entity/icon/EditIcon';
import TrashIcon from 'web/entity/icon/TrashIcon';
import {goToDetails, goToList} from 'web/entity/navigation';
import EntityTags from 'web/entity/Tags';
import withEntityContainer from 'web/entity/withEntityContainer';
import useTranslation from 'web/hooks/useTranslation';
import AlertComponent from 'web/pages/alerts/AlertComponent';
import AlertDetails from 'web/pages/alerts/Details';
import {selector, loadEntity} from 'web/store/entities/alerts';
import {
  loadAllEntities as loadAllReportFormats,
  selector as reportFormatsSelector,
} from 'web/store/entities/reportformats';
import PropTypes from 'web/utils/PropTypes';
export const ToolBarIcons = ({
  entity,
  onAlertCloneClick,
  onAlertCreateClick,
  onAlertDeleteClick,
  onAlertDownloadClick,
  onAlertEditClick,
}) => {
  const [_] = useTranslation();

  return (
    <Divider margin="10px">
      <IconDivider>
        <ManualIcon
          anchor="managing-alerts"
          page="scanning"
          title={_('Help: Alerts')}
        />
        <ListIcon page="alerts" title={_('Alerts List')} />
      </IconDivider>
      <IconDivider>
        <CreateIcon entity={entity} onClick={onAlertCreateClick} />
        <CloneIcon entity={entity} onClick={onAlertCloneClick} />
        <EditIcon entity={entity} onClick={onAlertEditClick} />
        <TrashIcon entity={entity} onClick={onAlertDeleteClick} />
        <ExportIcon
          title={_('Export Alert as XML')}
          value={entity}
          onClick={onAlertDownloadClick}
        />
      </IconDivider>
    </Divider>
  );
};

ToolBarIcons.propTypes = {
  entity: PropTypes.model.isRequired,
  onAlertCloneClick: PropTypes.func.isRequired,
  onAlertCreateClick: PropTypes.func.isRequired,
  onAlertDeleteClick: PropTypes.func.isRequired,
  onAlertDownloadClick: PropTypes.func.isRequired,
  onAlertEditClick: PropTypes.func.isRequired,
};

const Page = ({
  entity,
  reportFormats,
  onChanged,
  onDownloaded,
  onError,

  ...props
}) => {
  const [_] = useTranslation();

  return (
    <AlertComponent
      onCloneError={onError}
      onCloned={goToDetails('alert', props)}
      onCreated={goToDetails('alert', props)}
      onDeleteError={onError}
      onDeleted={goToList('alerts', props)}
      onDownloadError={onError}
      onDownloaded={onDownloaded}
      onSaved={onChanged}
    >
      {({clone, create, delete: delete_func, download, edit, save}) => (
        <EntityPage
          {...props}
          entity={entity}
          sectionIcon={<AlertIcon size="large" />}
          title={_('Alert')}
          toolBarIcons={ToolBarIcons}
          onAlertCloneClick={clone}
          onAlertCreateClick={create}
          onAlertDeleteClick={delete_func}
          onAlertDownloadClick={download}
          onAlertEditClick={edit}
          onAlertSaveClick={save}
        >
          {() => {
            return (
              <React.Fragment>
                <PageTitle title={_('Alert: {{name}}', {name: entity.name})} />
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
                        <AlertDetails
                          entity={entity}
                          reportFormats={reportFormats}
                        />
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
    </AlertComponent>
  );
};

Page.propTypes = {
  entity: PropTypes.model,
  reportFormats: PropTypes.array,
  onChanged: PropTypes.func.isRequired,
  onDownloaded: PropTypes.func.isRequired,
  onError: PropTypes.func.isRequired,
};

const load = gmp => {
  const loadEntityFunc = loadEntity(gmp);
  const loadAllReportFormatsFunc = loadAllReportFormats(gmp);
  return id => dispatch =>
    Promise.all([
      dispatch(loadEntityFunc(id)),
      dispatch(loadAllReportFormatsFunc()),
    ]);
};

const mapStateToProps = (rootState, {id}) => {
  const reportFormatsSel = reportFormatsSelector(rootState);
  return {
    reportFormats: reportFormatsSel.getAllEntities(),
  };
};

export default withEntityContainer('alert', {
  entitySelector: selector,
  load,
  mapStateToProps,
})(Page);

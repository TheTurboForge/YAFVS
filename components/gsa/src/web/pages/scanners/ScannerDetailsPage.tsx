/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useNavigate} from 'react-router';
import type Gmp from 'gmp/gmp';
import type Scanner from 'gmp/models/scanner';
import {ScannerIcon} from 'web/components/icon';
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
import {type OnDownloadedFunc} from 'web/entity/hooks/useEntityDownload';
import {goToDetails, goToList} from 'web/entity/navigation';
import EntityTags from 'web/entity/Tags';
import withEntityContainer from 'web/entity/withEntityContainer';
import useTranslation from 'web/hooks/useTranslation';
import ScannerComponent from 'web/pages/scanners/ScannerComponent';
import ScannerDetails from 'web/pages/scanners/ScannerDetails';
import ScannerDetailsPageToolBarIcons from 'web/pages/scanners/ScannerDetailsPageToolBarIcons';
import {selector, loadEntity} from 'web/store/entities/scanners';

interface ScannerDetailsPageProps {
  entity: Scanner;
  isLoading?: boolean;
  onChanged?: () => void;
  onDownloaded: OnDownloadedFunc;
  onError: (error: Error) => void;
  showSuccess: (message: string) => void;
}

const ScannerDetailsPage = ({
  entity,
  isLoading = false,
  onChanged,
  onDownloaded,
  onError,
  showSuccess,
}: ScannerDetailsPageProps) => {
  const [_] = useTranslation();
  const navigate = useNavigate();


  return (
    <ScannerComponent
      onCloneError={onError}
      onCloned={goToDetails('scanner', navigate)}
      onCreated={goToDetails('scanner', navigate)}
      onCredentialDownloadError={onError}
      onCredentialDownloaded={onDownloaded}
      onDeleteError={onError}
      onDeleted={goToList('scanners', navigate)}
      onDownloadError={onError}
      onDownloaded={onDownloaded}
      onSaved={onChanged}
      onVerified={() => {
        onChanged?.();
        showSuccess(_('Scanner Verified'));
      }}
      onVerifyError={onError}
    >
      {({
        clone,
        create,
        delete: deleteFunc,
        download,
        downloadCredential,
        edit,
        verify,
      }) => (
        <EntityPage<Scanner>
          entity={entity}
          entityType="scanner"
          isLoading={isLoading}
          sectionIcon={<ScannerIcon size="large" />}
          title={_('Scanner')}
          toolBarIcons={
            <ScannerDetailsPageToolBarIcons
              entity={entity}
              onScannerCloneClick={clone}
              onScannerCreateClick={create}
              onScannerCredentialDownloadClick={downloadCredential}
              onScannerDeleteClick={deleteFunc}
              onScannerDownloadClick={download}
              onScannerEditClick={edit}
              onScannerVerifyClick={verify}
            />
          }
        >
          {() => {
            return (
              <>
                <PageTitle
                  title={_('Scanner: {{name}}', {name: entity.name as string})}
                />
                <TabsContainer flex="column" grow="1">
                  <TabLayout align={['start', 'end']} grow="1">
                    <TabList align={['start', 'stretch']}>
                      <Tab>{_('Information')}</Tab>
                      <EntitiesTab entities={entity.userTags}>
                        {_('User Tags')}
                      </EntitiesTab>{' '}
                    </TabList>
                  </TabLayout>

                  <Tabs>
                    <TabPanels>
                      <TabPanel>
                        <ScannerDetails entity={entity} />
                      </TabPanel>
                      <TabPanel>
                        <EntityTags
                          entity={entity}
                          onChanged={onChanged}
                          onError={onError}
                        />
                      </TabPanel>{' '}
                    </TabPanels>
                  </Tabs>
                </TabsContainer>
              </>
            );
          }}
        </EntityPage>
      )}
    </ScannerComponent>
  );
};

const load = (gmp: Gmp) => {
  const loadEntityFunc = loadEntity(gmp);
  return (id: string) => dispatch =>
    Promise.all([
      dispatch(loadEntityFunc(id)),
    ]);
};

const mapStateToProps = (rootState, {id}: {id: string}) => {
  return {
  };
};

export default withEntityContainer('scanner', {
  entitySelector: selector,
  load,
  mapStateToProps,
})(ScannerDetailsPage);

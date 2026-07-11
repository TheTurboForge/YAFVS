/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useRef, useState} from 'react';
import {
  showSuccessNotification,
  showErrorNotification,
} from '@greenbone/ui-lib';
import styled from 'styled-components';
import {type TrashCanGetData} from 'gmp/commands/trashcan';
import type Rejection from 'gmp/http/rejection';
import type Model from 'gmp/models/model';
import {
  fetchNativeTrashcanSummary,
  NativeTrashcanEmptyIndeterminateError,
  NativeTrashcanEmptyPreviewChangedError,
  type NativeTrashcanApiGmp,
  type NativeTrashcanEmptyPreview,
  type NativeTrashcanSummary,
} from 'gmp/native-api/trashcan';
import {isDefined} from 'gmp/utils/identity';
import ConfirmationDialog from 'web/components/dialog/ConfirmationDialog';
import {DELETE_ACTION} from 'web/components/dialog/DialogTwoButtonFooter';
import {TrashcanIcon} from 'web/components/icon';
import Layout from 'web/components/layout/Layout';
import PageTitle from 'web/components/layout/PageTitle';
import LinkTarget from 'web/components/link/Target';
import Loading from 'web/components/loading/Loading';
import DialogNotification from 'web/components/notification/DialogNotification';
import useDialogNotification from 'web/components/notification/useDialogNotification';
import Section from 'web/components/section/Section';
import Table from 'web/components/table/StripedTable';
import TableHead from 'web/components/table/TableHead';
import TableHeader from 'web/components/table/TableHeader';
import TableRow from 'web/components/table/TableRow';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import AlertsTable from 'web/pages/alerts/Table';
import CredentialTable from 'web/pages/credentials/CredentialTable';
import TrashActions from 'web/pages/extras/TrashActions';
import FiltersTable from 'web/pages/filters/Table';
import OverridesTable from 'web/pages/overrides/Table';
import PortListTable from 'web/pages/portlists/PortListTable';
import ReportConfigsTable from 'web/pages/reportconfigs/Table';
import ReportFormatsTable from 'web/pages/reportformats/Table';
import ScanConfigsTable from 'web/pages/scanconfigs/Table';
import ScannerTable from 'web/pages/scanners/ScannerTable';
import SchedulesTable from 'web/pages/schedules/Table';
import TagsTable from 'web/pages/tags/TagTable';
import TargetsTable from 'web/pages/targets/TargetTable';
import TasksTable from 'web/pages/tasks/TaskTable';
import EmptyTrashButton from 'web/pages/trashcan/EmptyTrashButton';
import TrashCanPageToolBarIcons from 'web/pages/trashcan/TrashCanPageToolBarIcons';
import TrashCanTableContents from 'web/pages/trashcan/TrashCanTableContents';

interface TrashCanTableProps {
  links?: boolean;
  onEntityRestore?: (entity: Model) => Promise<void>;
  onEntityDelete?: (entity: Model) => Promise<void>;
  actionsComponent?: typeof TrashActions;
  footnote?: boolean;
  footer?: false | React.ComponentType;
}

type EmptyTrashDialogError =
  | 'empty-failed'
  | 'preview-failed'
  | 'preview-changed'
  | 'outcome-indeterminate';

const Col = styled.col`
  width: 50%;
`;

const hasEntities = (entities: Model[] | undefined): entities is Model[] => {
  return isDefined(entities) && entities.length > 0;
};

const hasNativeTrashcanApi = (
  candidate: unknown,
): candidate is NativeTrashcanApiGmp => {
  return (
    typeof (candidate as Partial<NativeTrashcanApiGmp>).buildUrl === 'function'
  );
};

const TrashCan = () => {
  const gmp = useGmp();
  const [isLoading, setIsLoading] = useState(false);
  const [isEmptyTrashDialogVisible, setIsEmptyTrashDialogVisible] =
    useState(false);
  const [isEmptyingTrash, setIsEmptyingTrash] = useState(false);
  const [isLoadingEmptyTrashPreview, setIsLoadingEmptyTrashPreview] =
    useState(false);
  const [emptyTrashPreview, setEmptyTrashPreview] = useState<
    NativeTrashcanEmptyPreview | undefined
  >();
  const [emptyTrashDialogError, setEmptyTrashDialogError] = useState<
    EmptyTrashDialogError | undefined
  >();
  const emptyTrashRequestInFlight = useRef(false);
  let [trash, setTrash] = useState<TrashCanGetData | undefined>();
  const [trashSummary, setTrashSummary] = useState<
    NativeTrashcanSummary | undefined
  >();
  const [_] = useTranslation();
  const {
    dialogState: notificationDialogState,
    closeDialog: closeNotificationDialog,
    showError,
  } = useDialogNotification();

  const loadTrash = useCallback(async () => {
    setIsLoading(true);
    const summaryRequest = hasNativeTrashcanApi(gmp)
      ? fetchNativeTrashcanSummary(gmp).catch(() => undefined)
      : Promise.resolve(undefined);

    try {
      const response = await gmp.trashcan.get();
      const summary = await summaryRequest;
      setTrash(response.data);
      setTrashSummary(summary);

      if (
        response.data.failedRequests &&
        response.data.failedRequests.length > 0
      ) {
        response.data.failedRequests.forEach(requestType => {
          showErrorNotification(
            '',
            _('Failed to load {{type}} from trashcan', {type: requestType}),
          );
        });
      }
    } catch (error) {
      showError(error as Rejection);
      setTrashSummary(undefined);
    } finally {
      setIsLoading(false);
    }
  }, [gmp, _, showError]);

  const handleRestore = async (entity: Model) => {
    try {
      await gmp.trashcan.restore({
        id: entity.id as string,
        entityType: entity.entityType,
      });
      void loadTrash();
      showSuccessNotification(
        _('{{- name}} restored successfully.', {name: entity.name as string}),
      );
    } catch (error) {
      showError(error as Rejection);
    }
  };

  const handleDelete = async (entity: Model) => {
    try {
      await gmp.trashcan.delete({
        id: entity.id as string,
        entityType: entity.entityType,
      });
      void loadTrash();
      showSuccessNotification(
        _('{{- name}} deleted successfully.', {name: entity.name as string}),
      );
    } catch (error) {
      showError(error as Rejection);
    }
  };

  const loadEmptyTrashPreview = useCallback(async () => {
    if (!hasNativeTrashcanApi(gmp)) {
      setEmptyTrashPreview(undefined);
      setEmptyTrashDialogError('preview-failed');
      return;
    }

    setIsLoadingEmptyTrashPreview(true);
    setEmptyTrashPreview(undefined);
    try {
      const preview = await gmp.trashcan.emptyPreview();
      setEmptyTrashPreview(preview);
    } catch {
      setEmptyTrashDialogError('preview-failed');
    } finally {
      setIsLoadingEmptyTrashPreview(false);
    }
  }, [gmp]);

  const handleEmpty = async () => {
    if (emptyTrashPreview === undefined) {
      setEmptyTrashDialogError(undefined);
      await Promise.all([loadTrash(), loadEmptyTrashPreview()]);
      return;
    }
    if (emptyTrashRequestInFlight.current) {
      return;
    }

    emptyTrashRequestInFlight.current = true;
    setIsEmptyingTrash(true);

    try {
      await gmp.trashcan.empty({expectedTotal: emptyTrashPreview.total});
      await loadTrash();
      closeEmptyTrashDialog();
    } catch (error) {
      if (error instanceof NativeTrashcanEmptyPreviewChangedError) {
        setEmptyTrashDialogError('preview-changed');
        await loadEmptyTrashPreview();
      } else if (error instanceof NativeTrashcanEmptyIndeterminateError) {
        setEmptyTrashPreview(undefined);
        setEmptyTrashDialogError('outcome-indeterminate');
        await loadTrash();
      } else {
        setEmptyTrashDialogError('empty-failed');
      }
    } finally {
      emptyTrashRequestInFlight.current = false;
      setIsEmptyingTrash(false);
    }
  };

  const closeEmptyTrashDialog = () => {
    setIsEmptyTrashDialogVisible(false);
    setEmptyTrashPreview(undefined);
    setEmptyTrashDialogError(undefined);
  };

  const openEmptyTrashDialog = () => {
    setIsEmptyTrashDialogVisible(true);
    setEmptyTrashPreview(undefined);
    setEmptyTrashDialogError(undefined);
    void loadEmptyTrashPreview();
  };

  const emptyTrashDialogContent = () => {
    if (emptyTrashDialogError === 'outcome-indeterminate') {
      return _(
        'The result could not be confirmed. Refresh the trashcan and obtain a new preview before trying again.',
      );
    }
    if (emptyTrashPreview === undefined) {
      return emptyTrashDialogError === 'preview-failed'
        ? _(
            'Unable to load a current trashcan preview. Refresh before trying again.',
          )
        : _('Loading the current trashcan preview.');
    }
    return (
      <>
        {emptyTrashDialogError === 'preview-changed' && (
          <p>
            {_(
              'Trashcan contents changed. Review the updated preview and confirm again.',
            )}
          </p>
        )}
        {emptyTrashDialogError === 'empty-failed' && (
          <p>
            {_('An error occurred while emptying the trash, please try again.')}
          </p>
        )}
        <p>{_('Are you sure you want to empty the trash?')}</p>
        <p>
          {_('Scope')}: {emptyTrashPreview.scope}
        </p>
        <p>
          {_('Items')}: {emptyTrashPreview.total}
        </p>
      </>
    );
  };

  // load the data on initial render
  useEffect(() => {
    void loadTrash();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const tableProps: TrashCanTableProps = {
    links: false,
    onEntityRestore: handleRestore,
    onEntityDelete: handleDelete,
    actionsComponent: TrashActions,
    footnote: false,
    footer: false,
  };

  if (!isDefined(trash) && isLoading) {
    return <Loading />;
  }
  return (
    <>
      <PageTitle title={_('Trashcan')} />
      <Layout flex="column">
        <span>
          {' '}
          {/* span prevents Toolbar from growing */}
          <TrashCanPageToolBarIcons />
        </span>
        <DialogNotification
          {...notificationDialogState}
          onCloseClick={closeNotificationDialog}
        />
        <Section img={<TrashcanIcon size="large" />} title={_('Trashcan')} />
        <EmptyTrashButton onClick={openEmptyTrashDialog} />
        {isEmptyTrashDialogVisible && (
          <ConfirmationDialog
            content={emptyTrashDialogContent()}
            loading={isEmptyingTrash || isLoading || isLoadingEmptyTrashPreview}
            rightButtonAction={DELETE_ACTION}
            rightButtonTitle={
              emptyTrashPreview === undefined ? _('Refresh') : _('Confirm')
            }
            title={_('Empty Trash')}
            width="500px"
            onClose={closeEmptyTrashDialog}
            onResumeClick={handleEmpty}
          />
        )}
        <LinkTarget id="Contents" />
        <h1>{_('Contents')}</h1>
        <Table>
          <colgroup>
            <Col />
            <Col />
          </colgroup>
          <TableHeader>
            <TableRow>
              <TableHead>{_('Type')}</TableHead>
              <TableHead>{_('Items')}</TableHead>
            </TableRow>
          </TableHeader>
          <TrashCanTableContents summary={trashSummary} trash={trash} />
        </Table>

        {hasEntities(trash?.alerts) && (
          <span>
            <LinkTarget id="alert" />
            <h1>{_('Alerts')}</h1>
            <AlertsTable entities={trash.alerts} {...tableProps} />
          </span>
        )}
        {hasEntities(trash?.credentials) && (
          <span>
            <LinkTarget id="credential" />
            <h1>{_('Credentials')}</h1>
            {/* @ts-expect-error */}
            <CredentialTable entities={trash.credentials} {...tableProps} />
          </span>
        )}
        {hasEntities(trash?.filters) && (
          <span>
            <LinkTarget id="filter" />
            <h1>{_('Filters')}</h1>
            <FiltersTable entities={trash.filters} {...tableProps} />
          </span>
        )}
        {hasEntities(trash?.overrides) && (
          <span>
            <LinkTarget id="override" />
            <h1>{_('Overrides')}</h1>
            {/* @ts-expect-error */}
            <OverridesTable entities={trash.overrides} {...tableProps} />
          </span>
        )}
        {hasEntities(trash?.portLists) && (
          <span>
            <LinkTarget id="port-list" />
            <h1>{_('Port Lists')}</h1>
            {/* @ts-expect-error */}
            <PortListTable entities={trash.portLists} {...tableProps} />
          </span>
        )}
        {hasEntities(trash?.reportConfigs) && (
          <span>
            <LinkTarget id="report-config" />
            <h1>{_('Report Configs')}</h1>
            <ReportConfigsTable
              entities={trash.reportConfigs}
              {...tableProps}
            />
          </span>
        )}
        {hasEntities(trash?.reportFormats) && (
          <span>
            <LinkTarget id="report-format" />
            <h1>{_('Report Formats')}</h1>
            <ReportFormatsTable
              entities={trash.reportFormats}
              {...tableProps}
            />
          </span>
        )}
        {hasEntities(trash?.scanConfigs) && (
          <span>
            <LinkTarget id="scan-config" />
            <h1>{_('Scan Configs')}</h1>
            <ScanConfigsTable entities={trash.scanConfigs} {...tableProps} />
          </span>
        )}
        {hasEntities(trash?.scanners) && (
          <span>
            <LinkTarget id="scanner" />
            <h1>{_('Scanners')}</h1>
            {/* @ts-expect-error */}
            <ScannerTable entities={trash.scanners} {...tableProps} />
          </span>
        )}
        {hasEntities(trash?.schedules) && (
          <span>
            <LinkTarget id="schedule" />
            <h1>{_('Schedules')}</h1>
            <SchedulesTable entities={trash.schedules} {...tableProps} />
          </span>
        )}
        {hasEntities(trash?.tags) && (
          <span>
            <LinkTarget id="tag" />
            <h1>{_('Tags')}</h1>
            <TagsTable entities={trash.tags} {...tableProps} />
          </span>
        )}
        {hasEntities(trash?.targets) && (
          <span>
            <LinkTarget id="target" />
            <h1>{_('Targets')}</h1>
            {/* @ts-expect-error */}
            <TargetsTable entities={trash.targets} {...tableProps} />
          </span>
        )}
        {hasEntities(trash?.tasks) && (
          <span>
            <LinkTarget id="task" />
            <h1>{_('Tasks')}</h1>
            {/* @ts-expect-error */}
            <TasksTable entities={trash.tasks} {...tableProps} />
          </span>
        )}
      </Layout>
    </>
  );
};

export default TrashCan;

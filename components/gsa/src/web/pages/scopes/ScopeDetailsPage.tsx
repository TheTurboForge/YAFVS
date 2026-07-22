/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useState} from 'react';
import {useNavigate, useParams} from 'react-router';
import type {ProtectionRequirement, Scope} from 'gmp/commands/scopes';
import {fetchNativeHosts} from 'gmp/native-api/hosts';
import {fetchNativeScope} from 'gmp/native-api/scopes';
import {fetchNativeTargets} from 'gmp/native-api/targets';
import Button from 'web/components/form/Button';
import MultiSelect from 'web/components/form/MultiSelect';
import Select from 'web/components/form/Select';
import TextArea from 'web/components/form/TextArea';
import TextField from 'web/components/form/TextField';
import Column from 'web/components/layout/Column';
import PageTitle from 'web/components/layout/PageTitle';
import Link from 'web/components/link/Link';
import Section from 'web/components/section/Section';
import Table from 'web/components/table/StripedTable';
import TableBody from 'web/components/table/TableBody';
import TableData from 'web/components/table/TableData';
import TableHead from 'web/components/table/TableHead';
import TableRow from 'web/components/table/TableRow';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import {
  EmptyRow,
  ErrorMessage,
  formatDate,
  PageActions,
  protectionRequirementItems,
  SummaryGrid,
  SummaryItem,
} from 'web/pages/scopes/common';

interface EntityOptionSource {
  id?: string;
  name?: string;
  ip?: string;
  hostname?: string;
}

interface EntityListCommand {
  get: (params: {filter: string}) => Promise<{data: EntityOptionSource[]}>;
}

const NATIVE_SELECTOR_PAGE_SIZE = 1000;

const canUseNativeApi = (gmp: {buildUrl?: unknown}) =>
  typeof gmp?.buildUrl === 'function';

const entityLabel = (entity: EntityOptionSource): string => {
  const name = entity.name || entity.hostname || entity.ip || entity.id || '';
  return entity.id && name !== entity.id ? `${name} (${entity.id})` : name;
};

const entityItems = (entities: EntityOptionSource[] = []) =>
  entities
    .filter(entity => entity.id)
    .map(entity => ({label: entityLabel(entity), value: entity.id as string}));

const mergeSelectedItems = (
  items: {label: string; value: string}[],
  selectedIds: string[],
  selectedEntities: EntityOptionSource[] = [],
) => {
  const itemMap = new Map(items.map(item => [item.value, item]));
  for (const entity of selectedEntities) {
    if (entity.id && !itemMap.has(entity.id)) {
      itemMap.set(entity.id, {label: entityLabel(entity), value: entity.id});
    }
  }
  for (const id of selectedIds) {
    if (!itemMap.has(id)) {
      itemMap.set(id, {label: id, value: id});
    }
  }
  return Array.from(itemMap.values()).sort((left, right) =>
    left.label.localeCompare(right.label),
  );
};

const addUnique = (values: string[], value?: string): string[] => {
  if (!value || values.includes(value)) {
    return values;
  }
  return [...values, value];
};

const loadNativeTargets = async (
  gmp: ReturnType<typeof useGmp>,
): Promise<EntityOptionSource[]> => {
  const targets: EntityOptionSource[] = [];
  let page = 1;
  let total = Number.POSITIVE_INFINITY;

  while (targets.length < total) {
    const response = await fetchNativeTargets(gmp, {
      page,
      pageSize: NATIVE_SELECTOR_PAGE_SIZE,
      sort: 'name',
      filter: '',
    });
    targets.push(...(response.targets as unknown as EntityOptionSource[]));
    total = response.counts.filtered;
    if (response.targets.length === 0) {
      break;
    }
    page += 1;
  }

  return targets;
};

const loadNativeHosts = async (
  gmp: ReturnType<typeof useGmp>,
): Promise<EntityOptionSource[]> => {
  const hosts: EntityOptionSource[] = [];
  let page = 1;
  let total = Number.POSITIVE_INFINITY;

  while (hosts.length < total) {
    const response = await fetchNativeHosts(gmp, {
      page,
      pageSize: NATIVE_SELECTOR_PAGE_SIZE,
      sort: 'name',
      filter: '',
    });
    hosts.push(...(response.hosts as unknown as EntityOptionSource[]));
    total = response.counts.filtered;
    if (response.hosts.length === 0) {
      break;
    }
    page += 1;
  }

  return hosts;
};

const loadTargetOptions = async (
  gmp: ReturnType<typeof useGmp>,
): Promise<EntityOptionSource[]> => {
  if (canUseNativeApi(gmp)) {
    return loadNativeTargets(gmp);
  }
  const targetsCommand = gmp.targets as unknown as EntityListCommand;
  const response = await targetsCommand.get({filter: 'rows=-1'});
  return response.data;
};

const loadHostOptions = async (
  gmp: ReturnType<typeof useGmp>,
): Promise<EntityOptionSource[]> => {
  if (canUseNativeApi(gmp)) {
    return loadNativeHosts(gmp);
  }
  const hostsCommand = (gmp as unknown as {hosts: EntityListCommand}).hosts;
  const response = await hostsCommand.get({filter: 'rows=-1'});
  return response.data;
};

const ScopeDetailsPage = () => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const navigate = useNavigate();
  const {id = ''} = useParams();
  const [scope, setScope] = useState<Scope>();
  const [name, setName] = useState('');
  const [comment, setComment] = useState('');
  const [protectionRequirement, setProtectionRequirement] =
    useState<ProtectionRequirement>('normal');
  const [targetIds, setTargetIds] = useState<string[]>([]);
  const [hostIds, setHostIds] = useState<string[]>([]);
  const [targetItems, setTargetItems] = useState<{label: string; value: string}[]>([]);
  const [hostItems, setHostItems] = useState<{label: string; value: string}[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  const loadScope = useCallback(async () => {
    if (!id) {
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      const [scopeData, targets, hosts] = await Promise.all([
        fetchNativeScope(gmp, id),
        loadTargetOptions(gmp),
        loadHostOptions(gmp),
      ]);
      if (scopeData) {
        setScope(scopeData);
        setName(scopeData.name);
        setComment(scopeData.comment ?? '');
        setProtectionRequirement(scopeData.protectionRequirement);
        const currentTargetIds = scopeData.targets.map(target => target.id);
        const currentHostIds = scopeData.hosts.map(host => host.id);
        setTargetIds(currentTargetIds);
        setHostIds(currentHostIds);
        setTargetItems(
          mergeSelectedItems(
            entityItems(targets),
            currentTargetIds,
            scopeData.targets,
          ),
        );
        setHostItems(
          mergeSelectedItems(
            entityItems(hosts),
            currentHostIds,
            scopeData.hosts,
          ),
        );
      } else {
        setScope(undefined);
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [gmp, id]);

  useEffect(() => {
    void loadScope();
  }, [loadScope]);

  const saveScope = useCallback(async () => {
    if (!scope) {
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      await gmp.scopes.modify({
        id: scope.id,
        name,
        comment,
        protectionRequirement,
        targetIds,
        hostIds,
      });
      await loadScope();
    } catch (err) {
      setError(String(err));
      setLoading(false);
    }
  }, [comment, gmp, hostIds, loadScope, name, protectionRequirement, scope, targetIds]);

  const generateReport = useCallback(async () => {
    if (!scope) {
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      await gmp.scopes.generateReport({id: scope.id});
      await loadScope();
    } catch (err) {
      setError(String(err));
      setLoading(false);
    }
  }, [gmp, loadScope, scope]);

  const deleteScope = useCallback(async () => {
    if (!scope || scope.global) {
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      await gmp.scopes.delete({id: scope.id});
      navigate('/scopes');
    } catch (err) {
      setError(String(err));
      setLoading(false);
    }
  }, [gmp, navigate, scope]);

  if (!scope) {
    return (
      <Column>
        <PageTitle title={_('Scope')} />
        <Section title={_('Scope')} />
        {error ? <ErrorMessage>{error}</ErrorMessage> : <span>{_('Loading...')}</span>}
      </Column>
    );
  }

  return (
    <Column>
      <PageTitle title={scope.name} />
      <Section title={scope.name} />
      <SummaryGrid>
        <SummaryItem label={_('Protection Requirement')} value={scope.protectionRequirementLabel} />
        <SummaryItem label={_('Targets')} value={scope.targetCount} />
        <SummaryItem label={_('Hosts')} value={scope.hostCount} />
        <SummaryItem label={_('Scope Reports')} value={scope.scopeReportCount} />
      </SummaryGrid>
      <PageActions>
        <TextField
          disabled={loading || scope.global}
          grow={1}
          title={_('Name')}
          value={name}
          onChange={setName}
        />
        <Select<ProtectionRequirement>
          disabled={loading || scope.global}
          items={protectionRequirementItems}
          label={_('Protection Requirement')}
          value={protectionRequirement}
          onChange={setProtectionRequirement}
        />
        <Button
          disabled={loading || scope.global || !name.trim()}
          title={_('Save')}
          onClick={() => void saveScope()}
        />
        <Button
          disabled={loading}
          title={_('Generate Report')}
          onClick={() => void generateReport()}
        />
        <Button
          disabled={loading || scope.global}
          title={_('Delete')}
          onClick={() => void deleteScope()}
        />
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadScope()}
        />
      </PageActions>
      <TextArea
        disabled={loading || scope.global}
        minRows={2}
        title={_('Comment')}
        value={comment}
        onChange={setComment}
      />
      <MultiSelect
        disabled={loading || scope.global}
        items={targetItems}
        label={_('Targets')}
        name="target_ids"
        placeholder={_('Select scope targets')}
        value={targetIds}
        onChange={setTargetIds}
      />
      <MultiSelect
        disabled={loading || scope.global}
        items={hostItems}
        label={_('Hosts')}
        name="host_ids"
        placeholder={_('Select scope hosts')}
        value={hostIds}
        onChange={setHostIds}
      />
      {error && <ErrorMessage>{error}</ErrorMessage>}

      <Section title={_('Targets')} />
      <Table>
        <TableBody>
          <TableRow>
            <TableHead>{_('Name')}</TableHead>
            <TableHead>{_('ID')}</TableHead>
          </TableRow>
          {scope.targets.length === 0 && <EmptyRow colSpan={2} />}
          {scope.targets.map(target => (
            <TableRow key={target.id}>
              <TableData>
                <Link to={`/target/${target.id}`}>{target.name || target.id}</Link>
              </TableData>
              <TableData>{target.id}</TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Section title={_('Hosts')} />
      <Table>
        <TableBody>
          <TableRow>
            <TableHead>{_('Name')}</TableHead>
            <TableHead>{_('ID')}</TableHead>
          </TableRow>
          {scope.hosts.length === 0 && <EmptyRow colSpan={2} />}
          {scope.hosts.map(host => (
            <TableRow key={host.id}>
              <TableData>
                <Link to={`/host/${host.id}`}>{host.name || host.id}</Link>
              </TableData>
              <TableData>{host.id}</TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Section title={_('Candidate Hosts')} />
      <Table>
        <TableBody>
          <TableRow>
            <TableHead>{_('Host')}</TableHead>
            <TableHead>{_('Target')}</TableHead>
            <TableHead>{_('Source Report')}</TableHead>
            <TableHead>{_('Host ID')}</TableHead>
            <TableHead>{_('Actions')}</TableHead>
          </TableRow>
          {scope.candidateHosts.length === 0 && <EmptyRow colSpan={5} />}
          {scope.candidateHosts.map(host => (
            <TableRow key={`${host.id}-${host.targetId ?? ''}`}>
              <TableData>{host.name || host.id}</TableData>
              <TableData>{host.targetName || host.targetId || '-'}</TableData>
              <TableData>
                {host.sourceReportId ? (
                  <Link to={`/report/${host.sourceReportId}`}>{host.sourceReportId}</Link>
                ) : (
                  '-'
                )}
              </TableData>
              <TableData>{host.id}</TableData>
              <TableData>
                <Button
                  disabled={loading || scope.global || hostIds.includes(host.id)}
                  title={hostIds.includes(host.id) ? _('Added') : _('Add to Scope')}
                  onClick={() => setHostIds(current => addUnique(current, host.id))}
                />
              </TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Section title={_('Scope Reports')} />
      <Table>
        <TableBody>
          <TableRow>
            <TableHead>{_('Name')}</TableHead>
            <TableHead>{_('Created')}</TableHead>
            <TableHead>{_('Source Reports')}</TableHead>
            <TableHead>{_('Hosts With Evidence')}</TableHead>
            <TableHead>{_('Vulnerabilities')}</TableHead>
          </TableRow>
          {scope.scopeReports.length === 0 && <EmptyRow colSpan={5} />}
          {scope.scopeReports.map(report => (
            <TableRow key={report.id}>
              <TableData>
                <Link to={`/scopes/${scope.id}/reports/${report.id}`}>{report.name}</Link>
              </TableData>
              <TableData>{formatDate(report.created)}</TableData>
              <TableData>{report.sourceReportCount}</TableData>
              <TableData>{report.hostsWithEvidence}</TableData>
              <TableData>{report.vulnerabilitiesTotal}</TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Column>
  );
};

export default ScopeDetailsPage;

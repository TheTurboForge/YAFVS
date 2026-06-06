/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useState} from 'react';
import {useNavigate, useParams} from 'react-router';
import type {ProtectionRequirement, Scope} from 'gmp/commands/scopes';
import Button from 'web/components/form/Button';
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
  splitIds,
  SummaryGrid,
  SummaryItem,
} from 'web/pages/scopes/common';

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
  const [targetIds, setTargetIds] = useState('');
  const [hostIds, setHostIds] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  const loadScope = useCallback(async () => {
    if (!id) {
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      const response = await gmp.scopes.getOne(id);
      setScope(response.data);
      if (response.data) {
        setName(response.data.name);
        setComment(response.data.comment ?? '');
        setProtectionRequirement(response.data.protectionRequirement);
        setTargetIds(response.data.targets.map(target => target.id).join('\n'));
        setHostIds(response.data.hosts.map(host => host.id).join('\n'));
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
        targetIds: splitIds(targetIds),
        hostIds: splitIds(hostIds),
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
      <TextArea
        disabled={loading || scope.global}
        minRows={4}
        title={_('Target IDs')}
        value={targetIds}
        onChange={setTargetIds}
      />
      <TextArea
        disabled={loading || scope.global}
        minRows={4}
        title={_('Host IDs')}
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
          </TableRow>
          {scope.candidateHosts.length === 0 && <EmptyRow colSpan={4} />}
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
                <Link to={`/scope-report/${report.id}`}>{report.name}</Link>
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

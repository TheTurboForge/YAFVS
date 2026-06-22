/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useState} from 'react';
import type {ProtectionRequirement, Scope} from 'gmp/commands/scopes';
import {fetchNativeScopes} from 'gmp/native-api/scopes';
import Button from 'web/components/form/Button';
import Select from 'web/components/form/Select';
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
  PageActions,
  protectionRequirementItems,
} from 'web/pages/scopes/common';

const ScopeListPage = () => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [name, setName] = useState('');
  const [protectionRequirement, setProtectionRequirement] =
    useState<ProtectionRequirement>('normal');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  const loadScopes = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      setScopes(await fetchNativeScopes(gmp));
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [gmp]);

  useEffect(() => {
    void loadScopes();
  }, [loadScopes]);

  const createScope = useCallback(async () => {
    if (!name.trim()) {
      return;
    }
    setLoading(true);
    setError(undefined);
    try {
      await gmp.scopes.create({
        name: name.trim(),
        protectionRequirement,
      });
      setName('');
      setProtectionRequirement('normal');
      await loadScopes();
    } catch (err) {
      setError(String(err));
      setLoading(false);
    }
  }, [gmp, loadScopes, name, protectionRequirement]);

  const generateReport = useCallback(
    async (scopeId: string) => {
      setLoading(true);
      setError(undefined);
      try {
        await gmp.scopes.generateReport({id: scopeId});
        await loadScopes();
      } catch (err) {
        setError(String(err));
        setLoading(false);
      }
    },
    [gmp, loadScopes],
  );

  return (
    <Column>
      <PageTitle title={_('Scopes')} />
      <Section title={_('Scopes')} />
      <PageActions>
        <TextField
          disabled={loading}
          grow={1}
          placeholder={_('Scope name')}
          title={_('Name')}
          value={name}
          onChange={setName}
        />
        <Select<ProtectionRequirement>
          disabled={loading}
          items={protectionRequirementItems}
          label={_('Protection Requirement')}
          value={protectionRequirement}
          onChange={setProtectionRequirement}
        />
        <Button
          disabled={loading || !name.trim()}
          title={_('Create')}
          onClick={() => void createScope()}
        />
        <Button
          disabled={loading}
          title={_('Reload')}
          onClick={() => void loadScopes()}
        />
        <Link to="/scopes/reports">{_('Scope Reports')}</Link>
      </PageActions>
      {error && <ErrorMessage>{error}</ErrorMessage>}
      <Table>
        <TableBody>
          <TableRow>
            <TableHead>{_('Name')}</TableHead>
            <TableHead>{_('Protection Requirement')}</TableHead>
            <TableHead>{_('Targets')}</TableHead>
            <TableHead>{_('Hosts')}</TableHead>
            <TableHead>{_('Scope Reports')}</TableHead>
            <TableHead>{_('Actions')}</TableHead>
          </TableRow>
          {scopes.length === 0 && <EmptyRow colSpan={6} />}
          {scopes.map(scope => (
            <TableRow key={scope.id}>
              <TableData>
                <Link to={`/scopes/${scope.id}`}>{scope.name}</Link>
              </TableData>
              <TableData>{scope.protectionRequirementLabel}</TableData>
              <TableData>{scope.targetCount}</TableData>
              <TableData>{scope.hostCount}</TableData>
              <TableData>
                <Link to="/scopes/reports">{scope.scopeReportCount}</Link>
              </TableData>
              <TableData>
                <PageActions>
                  <Button
                    disabled={loading}
                    title={_('Generate Report')}
                    onClick={() => void generateReport(scope.id)}
                  />
                  <Link to={`/scopes/${scope.id}`}>{_('Open')}</Link>
                </PageActions>
              </TableData>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Column>
  );
};

export default ScopeListPage;

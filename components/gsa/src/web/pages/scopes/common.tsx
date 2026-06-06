/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {type ReactNode} from 'react';
import styled from 'styled-components';
import type {SelectItem} from 'web/components/form/Select';
import TableData from 'web/components/table/TableData';
import TableRow from 'web/components/table/TableRow';
import useTranslation from 'web/hooks/useTranslation';
import Theme from 'web/utils/Theme';

export const protectionRequirementItems: SelectItem[] = [
  {label: 'Normal', value: 'normal'},
  {label: 'High', value: 'high'},
  {label: 'Very High', value: 'very_high'},
];

export const splitIds = (value: string): string[] =>
  value
    .split(/[\s,;]+/)
    .map(id => id.trim())
    .filter(Boolean);

export const formatDate = (value?: string): string => {
  if (!value) {
    return '-';
  }
  const trimmed = value.trim();
  const numericValue = Number(trimmed);
  const date = /^\d+$/.test(trimmed) && Number.isFinite(numericValue)
    ? new Date(numericValue * 1000)
    : new Date(trimmed);
  if (Number.isNaN(date.valueOf())) {
    return value;
  }
  return date.toLocaleString();
};

export const EmptyRow = ({colSpan}: {colSpan: number}) => {
  const [_] = useTranslation();
  return (
    <TableRow>
      <TableData colSpan={colSpan}>{_('No entries')}</TableData>
    </TableRow>
  );
};

export const SummaryGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
  width: 100%;
`;

const SummaryTile = styled.div`
  border: 1px solid ${Theme.lightGray};
  border-radius: 4px;
  padding: 12px;
  background: ${Theme.white};
`;

const SummaryLabel = styled.div`
  color: ${Theme.darkGray};
  font-size: 0.9em;
`;

const SummaryValue = styled.div`
  font-size: 1.4em;
  font-weight: 600;
  margin-top: 4px;
`;

export const SummaryItem = ({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) => (
  <SummaryTile>
    <SummaryLabel>{label}</SummaryLabel>
    <SummaryValue>{value}</SummaryValue>
  </SummaryTile>
);

export const PageActions = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: end;
`;

export const ErrorMessage = styled.div`
  color: ${Theme.errorRed};
  font-weight: 600;
`;

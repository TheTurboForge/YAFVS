/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import styled from 'styled-components';
import CheckBox from 'web/components/form/Checkbox';
import FormGroup from 'web/components/form/FormGroup';
import useTranslation from 'web/hooks/useTranslation';
import Theme from 'web/utils/Theme';

interface ComposerContentProps {
  filterFieldTitle?: string;
  filterString: string;
  includeOverrides: boolean;
  onValueChange?: (value: boolean, name?: string) => void;
}

export const COMPOSER_CONTENT_DEFAULTS = {
  includeOverrides: true,
};

const FilterField = styled.div`
  display: block;
  min-height: 22px;
  color: ${Theme.darkGray};
  border: 1px solid ${Theme.inputBorderGray};
  border-radius: 2px;
  padding: 3px 8px;
  cursor: not-allowed;
  background-color: ${Theme.dialogGray};
  width: 100%;
`;

const ComposerContent = ({
  filterFieldTitle,
  filterString,
  includeOverrides,
  onValueChange,
}: ComposerContentProps) => {
  const [_] = useTranslation();
  filterFieldTitle =
    filterFieldTitle ||
    _(
      'To change the filter, please filter your results on the report page. This filter will not be stored as default.',
    );
  return (
    <>
      <FormGroup title={_('Results Filter')}>
        <FilterField title={filterFieldTitle}>{filterString}</FilterField>
      </FormGroup>
      <FormGroup direction="row" title={_('Include')}>
        <CheckBox
          checked={includeOverrides}
          checkedValue={true}
          data-testid="include-overrides"
          name="includeOverrides"
          title={_('Overrides')}
          unCheckedValue={false}
          onChange={onValueChange}
        />
        <CheckBox
          checked={true}
          checkedValue={true}
          data-testid="include-tls-cert"
          disabled={true}
          name="includeTlsCertificates"
          title={_('TLS Certificates')}
          toolTipTitle={_('TLS Certificates are always included for now')}
          unCheckedValue={false}
          onChange={onValueChange}
        />
      </FormGroup>
    </>
  );
};

export default ComposerContent;

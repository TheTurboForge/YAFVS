/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import FormGroup from 'web/components/form/FormGroup';
import Spinner from 'web/components/form/Spinner';
import Row from 'web/components/layout/Row';
import useTranslation from 'web/hooks/useTranslation';

interface AutoDeleteReportsGroupProps {
  autoDeleteData?: number;
  onChange?: (value: string | number, name: string) => void;
}

const AutoDeleteReportsGroup = ({
  autoDeleteData,
  onChange,
}: AutoDeleteReportsGroupProps) => {
  const [_] = useTranslation();
  return (
    <FormGroup title={_('Raw Report Retention')}>
      <Row>
        <span>{_('Keep newest')}</span>
        <Spinner
          max={1200}
          min={2}
          name="auto_delete_data"
          type="int"
          value={autoDeleteData}
          onChange={
            onChange as ((value: number, name?: string) => void) | undefined
          }
        />
        <span>
          {_('raw reports; older unreferenced reports are deleted automatically')}
        </span>
      </Row>
    </FormGroup>
  );
};

export default AutoDeleteReportsGroup;

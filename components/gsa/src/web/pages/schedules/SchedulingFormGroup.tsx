/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {TimePicker} from '@greenbone/ui-lib';
import type {Date} from 'gmp/models/date';
import Button from 'web/components/form/Button';
import DatePicker from 'web/components/form/DatePicker';
import FormGroup from 'web/components/form/FormGroup';
import Row from 'web/components/layout/Row';
import useTranslation from 'web/hooks/useTranslation';

interface SchedulingFormGroupProps {
  startDate: Date;
  startTime: string;
  handleStartDateChange: (newDate: Date, name: string) => void;
  handleTimeChange: (selectedTime: string, type: string) => void;
  handleNowButtonClick: () => void;
}

const SchedulingFormGroup = ({
  startDate,
  startTime,
  handleStartDateChange,
  handleTimeChange,
  handleNowButtonClick,
}: SchedulingFormGroupProps) => {
  const [_] = useTranslation();
  const formGroup = (
    <FormGroup title={_('Scheduling')}>
      <Row align={'end'} flex="row" gap={'lg'}>
        <DatePicker
          label={_('Start Date')}
          name="startDate"
          value={startDate}
          onChange={handleStartDateChange}
        />
        <TimePicker
          label={_('Start Time')}
          name="startDate"
          value={startTime}
          onChange={newStartTime => handleTimeChange(newStartTime, 'startTime')}
        />
        <Button title={_('Now')} onClick={handleNowButtonClick} />
      </Row>
    </FormGroup>
  );

  return formGroup;
};

export default SchedulingFormGroup;

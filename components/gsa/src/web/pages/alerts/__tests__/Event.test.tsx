/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {render, screen} from 'web/testing';
import {
  EVENT_TYPE_UPDATED_SECINFO,
  EVENT_TYPE_NEW_SECINFO,
  EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
} from 'gmp/models/alert';
import Event from 'web/pages/alerts/Event';

describe('Event Component', () => {
  test('should render null when event type is undefined', () => {
    const {container} = render(<Event />);
    expect(container.firstChild).toBeNull();
  });

  test('should render event type when only redacted type metadata is available', () => {
    render(<Event event={{type: EVENT_TYPE_TASK_RUN_STATUS_CHANGED}} />);
    expect(screen.getByText('Task run status changed')).toBeInTheDocument();
  });

  test('should render "New CVE arrived" for EVENT_TYPE_NEW_SECINFO', () => {
    const event = {
      type: EVENT_TYPE_NEW_SECINFO,
      data: {secinfo_type: {value: 'cve'}},
    };
    render(<Event event={event} />);
    expect(screen.getByText('New CVE arrived')).toBeInTheDocument();
  });

  test("should render 'New SecInfo arrived' when secinfo_type is undefined", () => {
    const event = {
      type: EVENT_TYPE_NEW_SECINFO,
      data: {},
    };
    render(<Event event={event} />);
    expect(screen.getByText('New SecInfo arrived')).toBeInTheDocument();
  });

  test('should render "Updated CPE arrived" for EVENT_TYPE_UPDATED_SECINFO', () => {
    const event = {
      type: EVENT_TYPE_UPDATED_SECINFO,
      data: {secinfo_type: {value: 'cpe'}},
    };
    render(<Event event={event} />);
    expect(screen.getByText('Updated CPE arrived')).toBeInTheDocument();
  });

  test('should render "Updated SecInfo arrived" when secinfo_type is undefined', () => {
    const event = {
      type: EVENT_TYPE_UPDATED_SECINFO,
      data: {},
    };
    render(<Event event={event} />);
    expect(screen.getByText('Updated SecInfo arrived')).toBeInTheDocument();
  });

  test('should render task run status for EVENT_TYPE_TASK_RUN_STATUS_CHANGED', () => {
    const event = {
      type: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      data: {status: {value: 'Running'}},
    };
    render(<Event event={event} />);
    expect(
      screen.getByText('Task run status changed to Running'),
    ).toBeInTheDocument();
  });

  test('should render "Task run status changed" when status is undefined', () => {
    const event = {
      type: EVENT_TYPE_TASK_RUN_STATUS_CHANGED,
      data: {},
    };
    render(<Event event={event} />);
    expect(screen.getByText('Task run status changed')).toBeInTheDocument();
  });

  test('should render event type as fallback for unknown event types', () => {
    const event = {type: 'UNKNOWN_EVENT', data: {}};
    render(<Event event={event} />);
    expect(screen.getByText('UNKNOWN_EVENT')).toBeInTheDocument();
  });
});

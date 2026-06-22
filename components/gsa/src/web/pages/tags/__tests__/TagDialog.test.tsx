/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  changeInputValue,
  fireEvent,
  getSelectItemElementsForSelect,
  rendererWith,
  screen,
  wait,
} from 'web/testing';
import Response from 'gmp/http/response';
import ResourceName from 'gmp/models/resource-name';
import TagDialog, {SELECT_MAX_RESOURCES} from 'web/pages/tags/TagDialog';

interface CreateGmpOptions {
  getResourceNamesResponse?: Response<ResourceName[]>;
  getResourceNames?: ReturnType<typeof testing.fn>;
  buildUrl?: (path: string, params?: unknown) => string;
  session?: {
    jwt?: string;
    token?: string;
  };
}

const createGmp = ({
  getResourceNamesResponse = new Response([
    new ResourceName({id: '123', name: 'Task', type: 'task'}),
  ]),
  getResourceNames = testing.fn().mockResolvedValue(getResourceNamesResponse),
  buildUrl,
  session,
}: CreateGmpOptions = {}) => ({
  settings: {},
  ...(buildUrl === undefined ? {} : {buildUrl}),
  ...(session === undefined ? {} : {session}),
  resourcenames: {
    getAll: getResourceNames,
    get: getResourceNames,
  },
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('TagDialog tests', () => {
  test('should render and handle close', () => {
    const onClose = testing.fn();
    const {render} = rendererWith({
      gmp: createGmp(),
    });
    render(<TagDialog onClose={onClose} />);

    const dialog = screen.getDialog();
    expect(dialog).toBeInTheDocument();
    expect(screen.getDialogTitle()).toHaveTextContent('New Tag');

    expect(screen.getDialogCloseButton()).toHaveTextContent('Cancel');
    expect(screen.getDialogSaveButton()).toHaveTextContent('Save');

    expect(screen.getByLabelText('Name')).toHaveValue('default:unnamed');
    expect(screen.getByLabelText('Comment')).toHaveValue('');
    expect(screen.getByLabelText('Value')).toHaveValue('');

    expect(screen.getByName('resourceType')).toHaveValue('');
    expect(screen.getByName('resourceIds')).toHaveValue('');
    expect(screen.getByName('resourceIdText')).toHaveValue('');
    const activeOptions = screen.getAllByName('active');
    expect(activeOptions[0]).toBeChecked();
    expect(activeOptions[1]).not.toBeChecked();

    fireEvent.click(screen.getDialogCloseButton());
    expect(onClose).toHaveBeenCalled();
  });

  test('should allow to save the dialog', async () => {
    const onSave = testing.fn();
    const {render} = rendererWith({
      gmp: createGmp(),
    });
    render(
      <TagDialog
        comment="New Tag"
        name="Some Tag"
        resourceIds={['123']}
        resourceType="task"
        resourceTypes={['task', 'report']}
        value="Some Value"
        onSave={onSave}
      />,
    );

    fireEvent.click(screen.getDialogSaveButton());

    expect(onSave).toHaveBeenCalledWith({
      id: undefined,
      active: true,
      comment: 'New Tag',
      name: 'Some Tag',
      resourceIds: ['123'],
      resourceType: 'task',
      value: 'Some Value',
    });
  });

  test('should allow to change form fields', async () => {
    const onSave = testing.fn();
    const {render} = rendererWith({
      gmp: createGmp(),
    });
    render(
      <TagDialog
        comment=""
        name=""
        resourceType="task"
        resourceTypes={['task', 'report']}
        value=""
        onSave={onSave}
      />,
    );

    // Change text fields
    changeInputValue(screen.getByLabelText('Name'), 'Changed Name');
    changeInputValue(screen.getByLabelText('Comment'), 'Changed Comment');
    changeInputValue(screen.getByLabelText('Value'), 'Changed Value');

    // Change resource type
    const resourceTypeSelect = screen.getByRole<HTMLSelectElement>('textbox', {
      name: 'Resource Type',
    });
    const resourceTypeOptions =
      await getSelectItemElementsForSelect(resourceTypeSelect);
    fireEvent.click(resourceTypeOptions[1]); // select 'report'

    fireEvent.click(screen.getDialogSaveButton());

    expect(onSave).toHaveBeenCalledWith({
      id: undefined,
      active: true,
      comment: 'Changed Comment',
      name: 'Changed Name',
      resourceIds: [],
      resourceType: 'report',
      value: 'Changed Value',
    });
  });

  test('should allow to select resource IDs and change active state', async () => {
    const onSave = testing.fn();
    const {render} = rendererWith({
      gmp: createGmp(),
    });
    render(
      <TagDialog
        active={true}
        comment="New Tag"
        name="Some Tag"
        resourceType="task"
        resourceTypes={['task', 'report']}
        value="Some Value"
        onSave={onSave}
      />,
    );

    // Wait for resource names to be loaded
    await wait();

    // Select resource ID from dropdown
    const resourceIdsSelect = screen.getByRole<HTMLSelectElement>('textbox', {
      name: 'Select Resource',
    });
    const resourceIdOptions =
      await getSelectItemElementsForSelect(resourceIdsSelect);
    fireEvent.click(resourceIdOptions[0]); // select first option

    // Change active state
    fireEvent.click(screen.getByLabelText('No'));

    fireEvent.click(screen.getDialogSaveButton());

    expect(onSave).toHaveBeenCalledWith({
      id: undefined,
      active: false,
      comment: 'New Tag',
      name: 'Some Tag',
      resourceIds: ['123'],
      resourceType: 'task',
      value: 'Some Value',
    });
  });

  test('should allow to add a resource uuid by text input', async () => {
    const onSave = testing.fn();
    const {render} = rendererWith({
      gmp: createGmp(),
    });
    render(
      <TagDialog
        resourceType="task"
        resourceTypes={['task', 'report']}
        onSave={onSave}
      />,
    );

    const resourceIdTextField = screen.getByLabelText('Add Resource by ID');
    changeInputValue(resourceIdTextField, '123');

    // let the change propagate
    await wait();

    // Press Enter to add the resource ID
    fireEvent.keyDown(resourceIdTextField, {key: 'Enter'});

    // let the async operation complete
    await wait();

    fireEvent.click(screen.getDialogSaveButton());

    expect(onSave).toHaveBeenCalledWith({
      id: undefined,
      active: true,
      comment: '',
      name: 'default:unnamed',
      resourceIds: ['123'],
      resourceType: 'task',
      value: '',
    });
  });

  test('should use native resource-name lookup for supported resource types', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 200, total: 1, sort: 'name', filter: ''},
        items: [{id: 'alert-native', type: 'alert', name: 'Native Alert'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const getResourceNames = testing.fn();
    const buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    const {render} = rendererWith({
      gmp: createGmp({
        buildUrl,
        getResourceNames,
        session: {jwt: 'jwt-token', token: 'test-token'},
      }),
    });

    render(<TagDialog resourceType="alert" resourceTypes={['alert']} />);

    await wait();

    expect(getResourceNames).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith(
      'api/v1/tags/resource-names/alert',
      {
        token: 'test-token',
        page: 1,
        page_size: SELECT_MAX_RESOURCES,
        sort: 'name',
        filter: '',
      },
    );
  });

  test('should use native resource-name lookup for scanner and schedule names', async () => {
    const fetchMock = testing.fn((url: string) =>
      Promise.resolve({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 200, total: 1, sort: 'name', filter: ''},
          items: [
            url.includes('/schedule')
              ? {id: 'schedule-native', type: 'schedule', name: 'Native Schedule'}
              : {id: 'scanner-native', type: 'scanner', name: 'Native Scanner'},
          ],
        }),
        ok: true,
        status: 200,
      }),
    );
    testing.stubGlobal('fetch', fetchMock);
    const getResourceNames = testing.fn();
    const buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    const {render} = rendererWith({
      gmp: createGmp({
        buildUrl,
        getResourceNames,
        session: {jwt: 'jwt-token', token: 'test-token'},
      }),
    });

    render(
      <TagDialog
        resourceType="scanner"
        resourceTypes={['scanner', 'schedule']}
      />,
    );
    await wait();
    render(
      <TagDialog
        resourceType="schedule"
        resourceTypes={['scanner', 'schedule']}
      />,
    );
    await wait();

    expect(getResourceNames).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith(
      'api/v1/tags/resource-names/scanner',
      {
        token: 'test-token',
        page: 1,
        page_size: SELECT_MAX_RESOURCES,
        sort: 'name',
        filter: '',
      },
    );
    expect(buildUrl).toHaveBeenCalledWith(
      'api/v1/tags/resource-names/schedule',
      {
        token: 'test-token',
        page: 1,
        page_size: SELECT_MAX_RESOURCES,
        sort: 'name',
        filter: '',
      },
    );
  });

  test('should keep unsupported resource-name lookups on inherited GMP', async () => {
    const getResourceNames = testing.fn().mockResolvedValue(
      new Response([new ResourceName({id: 'report-1', name: 'Report', type: 'report'})]),
    );
    const buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    const {render} = rendererWith({
      gmp: createGmp({
        buildUrl,
        getResourceNames,
        session: {jwt: 'jwt-token', token: 'test-token'},
      }),
    });

    render(<TagDialog resourceType="report" resourceTypes={['report']} />);

    await wait();

    expect(getResourceNames).toHaveBeenCalledWith({resourceType: 'report'});
    expect(buildUrl).not.toHaveBeenCalled();
  });

  test('should use native exact-id lookup when adding supported resources by id', async () => {
    const onSave = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 200, total: 1, sort: 'name', filter: ''},
        items: [{id: 'task-native', type: 'task', name: 'Native Task'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const getResourceNames = testing.fn();
    const buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    const {render} = rendererWith({
      gmp: createGmp({
        buildUrl,
        getResourceNames,
        session: {jwt: 'jwt-token', token: 'test-token'},
      }),
    });
    render(<TagDialog resourceType="task" resourceTypes={['task']} onSave={onSave} />);

    const resourceIdTextField = screen.getByLabelText('Add Resource by ID');
    changeInputValue(resourceIdTextField, 'task-native');
    await wait();
    fireEvent.keyDown(resourceIdTextField, {key: 'Enter'});
    await wait();
    fireEvent.click(screen.getDialogSaveButton());

    expect(getResourceNames).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenLastCalledWith(
      'api/v1/tags/resource-names/task',
      {
        token: 'test-token',
        page: 1,
        page_size: SELECT_MAX_RESOURCES,
        sort: 'name',
        filter: 'uuid=task-native',
      },
    );
    expect(onSave).toHaveBeenCalledWith({
      id: undefined,
      active: true,
      comment: '',
      name: 'default:unnamed',
      resourceIds: ['task-native'],
      resourceType: 'task',
      value: '',
    });
  });

  test('should show message when too many resources are selected', async () => {
    const onSave = testing.fn();
    const {render} = rendererWith({
      gmp: createGmp(),
    });
    render(
      <TagDialog
        resourceCount={SELECT_MAX_RESOURCES + 1}
        resourceType="task"
        resourceTypes={['task', 'report']}
        onSave={onSave}
      />,
    );

    expect(screen.getByText('Too many resources to list.'));
    expect(screen.queryByLabelText('Resource Type')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Select Resource')).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText('Add Resource by ID'),
    ).not.toBeInTheDocument();
  });

  test('should not allow to change resources if fixed', async () => {
    const onSave = testing.fn();
    const {render} = rendererWith({
      gmp: createGmp(),
    });
    render(
      <TagDialog
        fixed={true}
        resourceType="task"
        resourceTypes={['task', 'report']}
        onSave={onSave}
      />,
    );

    await wait();

    expect(screen.getByName('resourceType')).toBeDisabled();
    expect(screen.getByName('resourceIds')).toBeDisabled();
    expect(screen.getByLabelText('Add Resource by ID')).toBeDisabled();
  });
});

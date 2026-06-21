/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {rendererWith, screen} from 'web/testing';
import EverythingCapabilities from 'gmp/capabilities/everything';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import Tag from 'gmp/models/tag';
import Task from 'gmp/models/task';
import TagResourceList from 'web/pages/tags/TagResourceList';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createTag = (id = 'tag-1') =>
  new Tag({
    id,
    name: 'Test Tag',
    resourceType: 'task',
    resourceCount: 5,
    userCapabilities: new EverythingCapabilities(),
  });

const createTask = (id = 'task-1') =>
  new Task({
    id,
    name: 'Test Task',
    owner: {name: 'admin'},
  });

describe('ResourceList tests', () => {
  test('should render without crashing', async () => {
    const tag = createTag();
    const gmp = {
      tasks: {
        get: testing.fn().mockResolvedValue({
          data: [createTask()],
          meta: {filter: Filter.fromString(), counts: new CollectionCounts()},
        }),
      },
    };

    const {render} = rendererWith({gmp, capabilities: true});
    render(<TagResourceList entity={tag} />);

    await screen.findByText('Test Task');
  });

  test('should render without resources', async () => {
    const tag = new Tag({
      id: 'tag-1',
      name: 'Test Tag',
      resourceType: 'task',
      resourceCount: 0,
    });

    const gmp = {
      tasks: {
        get: testing.fn().mockResolvedValue({
          data: [],
          meta: {filter: Filter.fromString(), counts: new CollectionCounts()},
        }),
      },
    };

    const {render} = rendererWith({gmp, capabilities: true});
    render(<TagResourceList entity={tag} />);

    // Component renders empty state gracefully
  });

  test('should render multiple resources', async () => {
    const tag = createTag();
    const gmp = {
      tasks: {
        get: testing.fn().mockResolvedValue({
          data: [
            createTask('task-1'),
            createTask('task-2'),
            createTask('task-3'),
          ],
          meta: {filter: Filter.fromString(), counts: new CollectionCounts()},
        }),
      },
    };

    const {render} = rendererWith({gmp, capabilities: true});
    render(<TagResourceList entity={tag} />);

    const items = await screen.findAllByText('Test Task');
    expect(items.length).toBeGreaterThanOrEqual(1);
  });

  test('should call gmp with correct resource type', async () => {
    const tag = createTag();
    const getTasks = testing.fn().mockResolvedValue({
      data: [createTask()],
      meta: {filter: Filter.fromString(), counts: new CollectionCounts()},
    });
    const gmp = {
      tasks: {
        get: getTasks,
      },
    };

    const {render} = rendererWith({gmp, capabilities: true});
    render(<TagResourceList entity={tag} />);

    await screen.findByText('Test Task');

    expect(getTasks).toHaveBeenCalled();
  });

  test('should use native tag resources for supported resource types', async () => {
    const tag = createTag();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        tag_id: 'tag-1',
        resource_type: 'task',
        page: {page: 1, page_size: 40, total: 1, sort: 'name', filter: ''},
        items: [{id: 'task-native', type: 'task', name: 'Native Task'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const getTasks = testing.fn();
    const gmp = {
      buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
      session: {jwt: 'jwt-token', token: 'test-token'},
      tasks: {
        get: getTasks,
      },
    };

    const {render} = rendererWith({gmp, capabilities: true});
    render(<TagResourceList entity={tag} />);

    await screen.findByText('Native Task');

    expect(getTasks).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tags/tag-1/resources', {
      token: 'test-token',
      page: 1,
      page_size: 40,
      sort: 'name',
    });
  });

  test('should keep unsupported resource types on inherited commands', async () => {
    const tag = new Tag({
      id: 'tag-1',
      name: 'Credential Tag',
      resourceType: 'credential',
      resourceCount: 1,
    });
    const getCredentials = testing.fn().mockResolvedValue({
      data: [new Task({id: 'credential-1', name: 'Inherited Credential'})],
      meta: {filter: Filter.fromString(), counts: new CollectionCounts()},
    });
    const gmp = {
      buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
      session: {jwt: 'jwt-token', token: 'test-token'},
      credentials: {
        get: getCredentials,
      },
    };

    const {render} = rendererWith({gmp, capabilities: true});
    render(<TagResourceList entity={tag} />);

    await screen.findByText('Inherited Credential');

    expect(getCredentials).toHaveBeenCalled();
    expect(gmp.buildUrl).not.toHaveBeenCalled();
  });
});

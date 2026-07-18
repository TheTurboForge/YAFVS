/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  getSelectItemElementsForSelect,
  screen,
  within,
  rendererWith,
  fireEvent,
  wait,
} from 'web/testing';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import Tag from 'gmp/models/tag';
import Task from 'gmp/models/task';
import BulkTags from 'web/entities/BulkTags';
import SelectionType from 'web/utils/SelectionType';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('BulkTags tests', () => {
  test('should render the BulkTags component', () => {
    const entities = [new Task({id: '1'}), new Task({id: '2'})];
    const entitiesCounts = new CollectionCounts({filtered: 2, all: 2});
    const filter = Filter.fromString('');
    const selectedEntities = [];
    const onClose = testing.fn();
    const getAllTags = testing
      .fn()
      .mockResolvedValue({data: [new Tag({id: '1'})]});
    const gmp = {
      tags: {getAll: getAllTags},
    };
    const {render} = rendererWith({gmp, store: true});
    render(
      <BulkTags
        entities={entities}
        entitiesCounts={entitiesCounts}
        filter={filter}
        selectedEntities={selectedEntities}
        selectionType={SelectionType.SELECTION_PAGE_CONTENTS}
        onClose={onClose}
      />,
    );
    const dialog = screen.getDialog();
    expect(dialog).toBeInTheDocument();
  });

  test('should allow to tag all filtered entities', () => {
    const entities = [new Task({id: '1'}), new Task({id: '2'})];
    const entitiesCounts = new CollectionCounts({filtered: 2, all: 2});
    const filter = Filter.fromString('');
    const selectedEntities = [];
    const onClose = testing.fn();
    const getAllTags = testing
      .fn()
      .mockResolvedValue({data: [new Tag({id: '1'})]});
    const gmp = {
      tags: {getAll: getAllTags},
    };
    const {render} = rendererWith({gmp, store: true});
    render(
      <BulkTags
        entities={entities}
        entitiesCounts={entitiesCounts}
        filter={filter}
        selectedEntities={selectedEntities}
        selectionType={SelectionType.SELECTION_FILTER}
        onClose={onClose}
      />,
    );
    const title = screen.getDialogTitle();
    expect(title).toHaveTextContent('Add Tag to All Filtered');
  });

  test('should load selectable tags through the native API when available', async () => {
    const entities = [new Task({id: '1'}), new Task({id: '2'})];
    const entitiesCounts = new CollectionCounts({filtered: 2, all: 2});
    const filter = Filter.fromString('');
    const selectedEntities = [];
    const onClose = testing.fn();
    const getAllTags = testing.fn();
    const buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [{id: '1', name: 'Native tag', resource_type: 'task'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      buildUrl,
      session: {token: 'test-token'},
      tags: {getAll: getAllTags},
    };
    const {render} = rendererWith({gmp, store: true});

    render(
      <BulkTags
        entities={entities}
        entitiesCounts={entitiesCounts}
        filter={filter}
        selectedEntities={selectedEntities}
        selectionType={SelectionType.SELECTION_PAGE_CONTENTS}
        onClose={onClose}
      />,
    );

    await wait();

    expect(getAllTags).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith('api/v1/tags', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
      active: '',
      resource_type: 'task',
      value: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/tags',
      {
        credentials: 'include',
        headers: {Accept: 'application/json'},
      },
    );
  });

  test('should load selected tag detail through the native API when available', async () => {
    const entities = [new Task({id: '1'}), new Task({id: '2'})];
    const entitiesCounts = new CollectionCounts({filtered: 2, all: 2});
    const filter = Filter.fromString('');
    const selectedEntities = [];
    const onClose = testing.fn();
    const getAllTags = testing.fn();
    const getTag = testing.fn();
    const buildUrl = testing.fn(
      (path: string) => `https://yafvs.example/${path}`,
    );
    const fetchMock = testing.fn((url: string) => {
      if (url.endsWith('/api/v1/tags')) {
        return Promise.resolve({
          json: testing.fn().mockResolvedValue({
            page: {page: 1, page_size: 25, total: 2, sort: 'name', filter: ''},
            items: [
              {id: '1', name: 'Native tag 1', resource_type: 'task'},
              {id: '2', name: 'Native tag 2', resource_type: 'task'},
            ],
          }),
          ok: true,
          status: 200,
        });
      }
      if (url.endsWith('/api/v1/tags/2')) {
        return Promise.resolve({
          json: testing.fn().mockResolvedValue({
            id: '2',
            name: 'Native tag 2',
            resource_type: 'task',
            value: 'native-value',
            comment: 'native-comment',
          }),
          ok: true,
          status: 200,
        });
      }
      return Promise.reject(new Error(`Unexpected fetch URL: ${url}`));
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      buildUrl,
      session: {token: 'test-token'},
      tags: {getAll: getAllTags},
      tag: {get: getTag},
    };
    const {render} = rendererWith({gmp, store: true});

    render(
      <BulkTags
        entities={entities}
        entitiesCounts={entitiesCounts}
        filter={filter}
        selectedEntities={selectedEntities}
        selectionType={SelectionType.SELECTION_PAGE_CONTENTS}
        onClose={onClose}
      />,
    );

    const select = screen.getSelectElement();
    const selectItems = await getSelectItemElementsForSelect(select);
    fireEvent.click(selectItems[1]);
    await wait();

    expect(getAllTags).not.toHaveBeenCalled();
    expect(getTag).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith('api/v1/tags/2', {
      token: 'test-token',
    });
    expect(screen.getByText('native-value')).toBeInTheDocument();
    expect(screen.getByText('native-comment')).toBeInTheDocument();
  });

  test('should allow to tag tasks with a new tag', async () => {
    const entities = [new Task({id: '1'}), new Task({id: '2'})];
    const entitiesCounts = new CollectionCounts({filtered: 2, all: 2});
    const filter = Filter.fromString('');
    const selectedEntities = [];
    const onClose = testing.fn();
    const createTag = testing.fn().mockResolvedValue({data: {id: '2'}});
    const getTag = testing.fn().mockResolvedValue({data: new Tag({id: '2'})});
    const getAllTags = testing
      .fn()
      .mockResolvedValue({data: [new Tag({id: '1'})]});
    const saveTag = testing.fn().mockResolvedValue({data: {id: '2'}});
    const gmp = {
      tags: {getAll: getAllTags},
      tag: {
        create: createTag,
        get: getTag,
        save: saveTag,
      },
    };
    const {render} = rendererWith({gmp, store: true});
    render(
      <BulkTags
        entities={entities}
        entitiesCounts={entitiesCounts}
        filter={filter}
        selectedEntities={selectedEntities}
        selectionType={SelectionType.SELECTION_PAGE_CONTENTS}
        onClose={onClose}
      />,
    );

    const tagsDialog = within(screen.getDialog());
    const newTag = tagsDialog.getByTitle('Create a new Tag');
    fireEvent.click(newTag);

    const dialogs = screen.getAllByRole('dialog');
    expect(dialogs).toHaveLength(2);

    const tagDialog = within(dialogs[1]);
    const saveTagButton = tagDialog.getDialogSaveButton();
    fireEvent.click(saveTagButton);

    await wait();

    expect(createTag).toHaveBeenCalledWith({
      active: true,
      comment: '',
      name: 'default:unnamed',
      resourceIds: [],
      resourceType: 'task',
      value: '',
    });
    expect(getTag).toHaveBeenCalledWith({id: '2'});

    const saveTagsButton = tagsDialog.getDialogSaveButton();
    fireEvent.click(saveTagsButton);

    expect(saveTag).toHaveBeenCalledWith({
      active: true,
      comment: '',
      filter: undefined,
      id: '2',
      name: undefined,
      resourceIds: ['1', '2'],
      resourceType: 'task',
      resourcesAction: 'add',
      value: '',
    });
  });
});

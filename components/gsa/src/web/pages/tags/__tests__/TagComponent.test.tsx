/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {fireEvent, rendererWith, screen, wait} from 'web/testing';
import Response from 'gmp/http/response';
import ResourceName from 'gmp/models/resource-name';
import Setting from 'gmp/models/setting';
import Tag from 'gmp/models/tag';
import Task from 'gmp/models/task';
import {YES_VALUE} from 'gmp/parser';
import {createSession} from 'gmp/testing';
import Button from 'web/components/form/Button';
import TagComponent from 'web/pages/tags/TagComponent';
import {SELECT_MAX_RESOURCES} from 'web/pages/tags/TagDialog';

const createGmp = ({
  createTagResponse = {id: '123'},
  saveTagResponse = {id: '123'},
  getTagResponse = new Response(
    new Tag({
      id: '123',
      name: 'My Tag',
      comment: '',
      active: YES_VALUE,
      resourceType: 'task',
      value: 'Some Value',
    }),
  ),
  deleteTagResponse = undefined,
  cloneTagResponse = {id: '123'},
  downloadTagResponse = {data: 'some-data'},
  enableTagResponse = undefined,
  disableTagResponse = undefined,
  getTasksResponse = new Response([new Task({id: '1', name: 'Task 1'})]),
  getResourceNamesResponse = new Response([
    new ResourceName({id: '123', name: 'Task', type: 'task'}),
  ]),
  createTag = testing.fn().mockResolvedValue(createTagResponse),
  saveTag = testing.fn().mockResolvedValue(saveTagResponse),
  cloneTag = testing.fn().mockResolvedValue(cloneTagResponse),
  getTag = testing.fn().mockResolvedValue(getTagResponse),
  deleteTag = testing.fn().mockResolvedValue(deleteTagResponse),
  downloadTag = testing.fn().mockResolvedValue(downloadTagResponse),
  enableTag = testing.fn().mockResolvedValue(enableTagResponse),
  disableTag = testing.fn().mockResolvedValue(disableTagResponse),
  getTasks = testing.fn().mockResolvedValue(getTasksResponse),
  getResourceNames = testing.fn().mockResolvedValue(getResourceNamesResponse),
  native = false,
} = {}) => ({
  ...(native
    ? {
        buildUrl: testing.fn(
          (path, _params) => `https://turbovas.example/${path}`,
        ),
      }
    : {}),
  settings: {
    enableGreenboneSensor: true,
    enableKrb5: false,
  },
  session: {...createSession(), token: 'test-token', jwt: 'jwt-token'},
  user: {
    currentSettings: testing.fn().mockResolvedValue(
      new Response({
        detailsexportfilename: new Setting({
          _id: 'a6ac88c5-729c-41ba-ac0a-deea4a3441f2',
          name: 'Details Export File Name',
          value: '%T-%U',
        }),
      }),
    ),
  },
  tag: {
    clone: cloneTag,
    create: createTag,
    export: downloadTag,
    get: getTag,
    save: saveTag,
    enable: enableTag,
    disable: disableTag,
    delete: deleteTag,
  },
  tasks: {
    get: getTasks,
  },
});

const nativeTagPayload = {
  id: '1234',
  name: 'My Tag',
  comment: '',
  active: true,
  resource_type: 'task',
  resource_count: 1,
  value: 'Some Value',
};

const nativeTagResourcesPayload = {
  tag_id: '1234',
  resource_type: 'task',
  page: {page: 1, page_size: SELECT_MAX_RESOURCES, total: 1, sort: 'name'},
  items: [{id: '1', name: 'Task 1', type: 'task'}],
};

const nativeTagResourceNamesPayload = {
  page: {page: 1, page_size: SELECT_MAX_RESOURCES, total: 1, sort: 'name'},
  items: [{id: '1', name: 'Task 1', type: 'task'}],
};

const stubNativeFetch = (...payloads) => {
  const fetchMock = testing.fn();
  payloads.forEach(payload => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: testing.fn().mockResolvedValue(payload),
    });
  });
  testing.stubGlobal('fetch', fetchMock);
  return fetchMock;
};

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('TagComponent tests', () => {
  test('should render and allow to create a new tag', async () => {
    const gmp = createGmp();
    const {render} = rendererWith({gmp, capabilities: true});
    const onCreated = testing.fn();

    // Verify rendering
    render(
      <TagComponent onCreated={onCreated}>
        {({create}) => <Button data-testid="button" onClick={() => create()} />}
      </TagComponent>,
    );

    // Test create flow
    const button = screen.getByTestId('button');
    fireEvent.click(button);

    await wait();

    screen.getDialog();
    fireEvent.click(screen.getDialogSaveButton());

    await wait();

    expect(gmp.tag.create).toHaveBeenCalledWith({
      active: true,
      comment: '',
      id: undefined,
      name: 'default:unnamed',
      resourceIds: [],
      resourceType: undefined,
      value: '',
    });

    expect(onCreated).toHaveBeenCalled();
  });

  test('should use native tag reads to edit an existing tag', async () => {
    const fetchMock = stubNativeFetch(
      nativeTagPayload,
      nativeTagResourcesPayload,
      nativeTagResourceNamesPayload,
    );
    const gmp = createGmp({native: true});
    const tag = new Tag({name: 'My Tag', id: '1234', resourceType: 'task'});
    const onSaved = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TagComponent onSaved={onSaved}>
        {({edit}) => <Button data-testid="button" onClick={() => edit(tag)} />}
      </TagComponent>,
    );

    fireEvent.click(screen.getByTestId('button'));

    await wait();

    expect(gmp.tag.get).not.toHaveBeenCalled();
    expect(gmp.tasks.get).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tags/1234', {
      token: 'test-token',
    });
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tags/1234/resources', {
      token: 'test-token',
      page: 1,
      page_size: SELECT_MAX_RESOURCES,
      sort: 'name',
    });
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tags/resource-names/task', {
      token: 'test-token',
      page: 1,
      page_size: SELECT_MAX_RESOURCES,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);

    screen.getDialog();
    fireEvent.click(screen.getDialogSaveButton());

    await wait();

    expect(gmp.tag.save).toHaveBeenCalledWith({
      active: true,
      comment: '',
      id: '1234',
      name: 'My Tag',
      resourceIds: ['1'],
      resourceType: 'task',
      value: 'Some Value',
    });

    expect(onSaved).toHaveBeenCalled();
  });

  test('should create a tag with predefined resource type and ids', async () => {
    const gmp = createGmp();
    const {render} = rendererWith({gmp, capabilities: true});
    const onCreated = testing.fn();

    render(
      <TagComponent onCreated={onCreated}>
        {({create}) => (
          <Button
            data-testid="button"
            onClick={() =>
              create({
                resourceType: 'host',
                resourceIds: ['456', '789'],
              })
            }
          />
        )}
      </TagComponent>,
    );

    const button = screen.getByTestId('button');
    fireEvent.click(button);

    await wait();

    screen.getDialog();
    fireEvent.click(screen.getDialogSaveButton());

    await wait();

    expect(gmp.tag.create).toHaveBeenCalledWith({
      active: true,
      comment: '',
      id: undefined,
      name: 'default:unnamed',
      resourceIds: ['456', '789'],
      resourceType: 'host',
      value: '',
    });

    expect(onCreated).toHaveBeenCalled();
  });

  test('should allow to edit an existing tag', async () => {
    const gmp = createGmp();
    const tag = new Tag({name: 'My Tag', id: '1234', resourceType: 'task'});
    const onSaved = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TagComponent onSaved={onSaved}>
        {({edit}) => <Button data-testid="button" onClick={() => edit(tag)} />}
      </TagComponent>,
    );

    const button = screen.getByTestId('button');
    fireEvent.click(button);

    await wait();

    screen.getDialog();
    fireEvent.click(screen.getDialogSaveButton());

    await wait();

    expect(gmp.tag.save).toHaveBeenCalledWith({
      active: true,
      comment: '',
      id: '1234',
      name: 'My Tag',
      resourceIds: ['1'],
      resourceType: 'task',
      value: 'Some Value',
    });

    expect(onSaved).toHaveBeenCalled();
  });

  test('should allow to clone an existing tag', async () => {
    const gmp = createGmp();
    const tag = new Tag({name: 'My Tag', id: '1234', resourceType: 'task'});
    const onCloned = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TagComponent onCloned={onCloned}>
        {({clone}) => (
          <Button data-testid="button" onClick={() => clone(tag)} />
        )}
      </TagComponent>,
    );

    const button = screen.getByTestId('button');
    fireEvent.click(button);

    await wait();

    expect(gmp.tag.clone).toHaveBeenCalledWith({id: tag.id});
    expect(onCloned).toHaveBeenCalled();
  });

  test('should allow to download a tag', async () => {
    const gmp = createGmp();
    const tag = new Tag({name: 'My Tag', id: '1234', resourceType: 'task'});

    const {render} = rendererWith({gmp, capabilities: true});
    const onDownloaded = testing.fn();

    render(
      <TagComponent onDownloadError={onDownloaded} onDownloaded={onDownloaded}>
        {({download}) => (
          <Button data-testid="button" onClick={() => download(tag)} />
        )}
      </TagComponent>,
    );

    // allow user settings to load
    await wait();

    const button = screen.getByTestId('button');
    fireEvent.click(button);
    expect(gmp.tag.export).toHaveBeenCalledWith(tag);

    await wait();

    expect(onDownloaded).toHaveBeenCalledWith({
      data: 'some-data',
      filename: 'tag-1234.xml',
    });
  });

  test('should use native metadata export for downloads', async () => {
    const nativePayload = {
      id: '1234',
      name: 'My Tag',
      comment: 'native metadata',
      active: true,
      resource_type: 'task',
      resource_count: 1,
      value: 'Some Value',
    };
    const fetchMock = stubNativeFetch(nativePayload);
    const gmp = createGmp({native: true});
    const tag = new Tag({name: 'My Tag', id: '1234', resourceType: 'task'});
    const onDownloaded = testing.fn();
    const onDownloadError = testing.fn();
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TagComponent
        onDownloadError={onDownloadError}
        onDownloaded={onDownloaded}
      >
        {({download}) => (
          <Button data-testid="button" onClick={() => download(tag)} />
        )}
      </TagComponent>,
    );

    await wait();
    fireEvent.click(screen.getByTestId('button'));
    await wait();

    expect(gmp.tag.export).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tags/1234/export', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      'https://turbovas.example/api/v1/tags/1234/export',
      expect.objectContaining({credentials: 'include'}),
    );
    expect(onDownloaded).toHaveBeenCalledWith({
      data: `${JSON.stringify(nativePayload, null, 2)}\n`,
      filename: 'tag-1234.json',
    });
    expect(onDownloadError).not.toHaveBeenCalled();
  });

  test('should allow to enable and disable a tag', async () => {
    const tag = new Tag({name: 'My Tag', id: '1234', resourceType: 'task'});

    // Test enable
    const gmpEnable = createGmp();
    const onEnabled = testing.fn();
    let {render} = rendererWith({gmp: gmpEnable, capabilities: true});

    render(
      <TagComponent onEnabled={onEnabled}>
        {({enable}) => (
          <Button data-testid="enable-button" onClick={() => enable(tag)} />
        )}
      </TagComponent>,
    );

    fireEvent.click(screen.getByTestId('enable-button'));

    await wait();

    expect(gmpEnable.tag.enable).toHaveBeenCalledWith({id: tag.id});
    expect(onEnabled).toHaveBeenCalled();

    // Test disable
    const gmpDisable = createGmp();
    const onDisabled = testing.fn();
    ({render} = rendererWith({gmp: gmpDisable, capabilities: true}));

    render(
      <TagComponent onDisabled={onDisabled}>
        {({disable}) => (
          <Button data-testid="disable-button" onClick={() => disable(tag)} />
        )}
      </TagComponent>,
    );

    fireEvent.click(screen.getByTestId('disable-button'));

    await wait();

    expect(gmpDisable.tag.disable).toHaveBeenCalledWith({id: tag.id});
    expect(onDisabled).toHaveBeenCalled();
  });

  test('should allow to delete a tag', async () => {
    const gmp = createGmp();
    const tag = new Tag({name: 'My Tag', id: '1234', resourceType: 'task'});
    const onDeleted = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TagComponent onDeleted={onDeleted}>
        {({delete: deleteTag}) => (
          <Button data-testid="button" onClick={() => deleteTag(tag)} />
        )}
      </TagComponent>,
    );

    const button = screen.getByTestId('button');
    fireEvent.click(button);

    await wait();

    expect(gmp.tag.delete).toHaveBeenCalledWith({id: tag.id});
    expect(onDeleted).toHaveBeenCalled();
  });

  test('should allow to remove a tag', async () => {
    const gmp = createGmp();
    const onRemoved = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TagComponent onRemoved={onRemoved}>
        {({remove}) => (
          <Button
            data-testid="button"
            onClick={() => remove('123', new Task({id: '234'}))}
          />
        )}
      </TagComponent>,
    );

    const button = screen.getByTestId('button');
    fireEvent.click(button);

    await wait();

    expect(gmp.tag.save).toHaveBeenCalledWith({
      active: true,
      id: '123',
      name: 'My Tag',
      comment: '',
      resourceIds: ['234'],
      resourceType: 'task',
      resourcesAction: 'remove',
      value: 'Some Value',
    });
    expect(onRemoved).toHaveBeenCalled();
  });

  test('should use native tag detail to remove a tag from a resource', async () => {
    const fetchMock = stubNativeFetch(nativeTagPayload);
    const gmp = createGmp({native: true});
    const onRemoved = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TagComponent onRemoved={onRemoved}>
        {({remove}) => (
          <Button
            data-testid="button"
            onClick={() => remove('1234', new Task({id: '234'}))}
          />
        )}
      </TagComponent>,
    );

    fireEvent.click(screen.getByTestId('button'));

    await wait();

    expect(gmp.tag.get).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tags/1234', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(gmp.tag.save).toHaveBeenCalledWith({
      active: true,
      id: '1234',
      name: 'My Tag',
      comment: undefined,
      resourceIds: ['234'],
      resourceType: 'task',
      resourcesAction: 'remove',
      value: 'Some Value',
    });
    expect(onRemoved).toHaveBeenCalled();
  });
});

/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  rendererWith,
  screen,
  getSelectItemElementsForSelect,
  waitFor,
  userEvent,
  fireEvent,
  wait,
} from 'web/testing';
import Filter from 'gmp/models/filter';
import PortList from 'gmp/models/port-list';
import Tag from 'gmp/models/tag';
import {createSession} from 'gmp/testing';
import EntitiesContainer from 'web/entities/EntitiesContainer';

interface CreateGmpOptions {
  deleteEntities?: ReturnType<typeof testing.fn>;
  deleteByFilter?: ReturnType<typeof testing.fn>;
  exportByFilter?: ReturnType<typeof testing.fn>;
  currentSettings?: ReturnType<typeof testing.fn>;
  getAllTags?: ReturnType<typeof testing.fn>;
  getTag?: ReturnType<typeof testing.fn>;
  buildUrl?: ReturnType<typeof testing.fn>;
  session?: ReturnType<typeof createSession> & {token?: string};
}

const currentSettingsResponse = {
  data: {
    listexportfilename: {
      id: 'a6ac88c5-729c-41ba-ac0a-deea4a3441f2',
      name: 'List Export File Name',
      value: '%T-%U',
    },
  },
};

const setupTagBulk = gmp => {
  const {render} = rendererWith({gmp, store: true, router: true});
  const initialFilter = new Filter();
  render(
    <EntitiesContainer
      entities={[new PortList()]}
      filter={initialFilter}
      gmp={gmp}
      gmpName="portlist"
      isLoading={false}
      notify={notify}
      reload={reload}
      showError={showError}
      showErrorMessage={showErrorMessage}
      showSuccessMessage={showSuccessMessage}
      updateFilter={updateFilter}
      onDownload={onDownload}
    >
      {({onTagsBulk}) => (
        <button data-testid="tag-button" onClick={() => onTagsBulk()}>
          Tag Bulk
        </button>
      )}
    </EntitiesContainer>,
  );
  return screen.getByRole('button', {name: /Tag Bulk/i});
};

const onDownloaded = testing.fn();
const notify = testing.fn();
const updateFilter = testing.fn();
const reload = testing.fn();
const showError = testing.fn();
const showErrorMessage = testing.fn();
const showSuccessMessage = testing.fn();
const onDownload = testing.fn();

const setup = gmp => {
  const {render} = rendererWith({gmp, store: true, router: true});
  const initialFilter = new Filter();
  render(
    <EntitiesContainer
      entities={[new PortList()]}
      filter={initialFilter}
      gmp={gmp}
      gmpName="portlist"
      isLoading={false}
      notify={notify}
      reload={reload}
      showError={showError}
      showErrorMessage={showErrorMessage}
      showSuccessMessage={showSuccessMessage}
      updateFilter={updateFilter}
      onDownload={onDownload}
    >
      {({onDownloadBulk}) => (
        <button data-testid="button" onClick={() => onDownloadBulk()}>
          Download Bulk
        </button>
      )}
    </EntitiesContainer>,
  );
  return screen.getByRole('button', {name: /Download Bulk/i});
};

const setupDeleteBulk = (gmp, entities) => {
  const {render} = rendererWith({gmp, store: true, router: true});
  render(
    <EntitiesContainer
      entities={entities}
      filter={new Filter()}
      gmp={gmp}
      gmpName="tag"
      isLoading={false}
      notify={() => testing.fn()}
      reload={reload}
      showError={showError}
      showErrorMessage={showErrorMessage}
      showSuccessMessage={showSuccessMessage}
      updateFilter={updateFilter}
      onDownload={onDownload}
    >
      {({onDeleteBulk}) => (
        <button onClick={() => onDeleteBulk()}>Delete page</button>
      )}
    </EntitiesContainer>,
  );
  return screen.getByRole('button', {name: 'Delete page'});
};

const createGmp = ({
  deleteEntities = testing.fn().mockResolvedValue({data: []}),
  deleteByFilter = testing.fn().mockResolvedValue({data: []}),
  exportByFilter = testing.fn().mockResolvedValue({data: {id: '123'}}),
  currentSettings = testing.fn().mockResolvedValue(currentSettingsResponse),
  getAllTags = testing.fn().mockResolvedValue({data: []}),
  getTag = testing.fn().mockResolvedValue({data: {id: '1'}}),
  buildUrl,
  session = createSession(),
}: CreateGmpOptions = {}) => ({
  buildUrl,
  portlists: {
    exportByFilter,
  },
  tags: {delete: deleteEntities, deleteByFilter, getAll: getAllTags},
  tag: {get: getTag},
  user: {currentSettings},
  session,
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('EntitiesContainer', () => {
  test('should delete the exact loaded page entities', async () => {
    const deleteEntities = testing.fn().mockResolvedValue({data: []});
    const deleteByFilter = testing.fn().mockResolvedValue({data: []});
    const entities = [
      Tag.fromElement({_id: 'page-1'}),
      Tag.fromElement({_id: 'page-2'}),
    ];
    const gmp = createGmp({deleteEntities, deleteByFilter});

    fireEvent.click(setupDeleteBulk(gmp, entities));
    await wait();

    expect(deleteEntities).toHaveBeenCalledWith(entities);
    expect(deleteByFilter).not.toHaveBeenCalled();
  });

  test('should allow downloading entities in bulk', async () => {
    const gmp = createGmp();
    const downloadButton = setup(gmp);
    await userEvent.click(downloadButton);

    await waitFor(() => expect(screen.getByText('Bulk download started.')));
    expect(onDownload).toHaveBeenCalledWith({
      filename: 'portlists-list.xml',
      data: {id: '123'},
    });
    await waitFor(() => expect(screen.getByText('Bulk download completed.')));
  });

  test('should call onDownloadError when downloading entities in bulk fails', async () => {
    const error = 'mock error';
    const gmp = createGmp({
      exportByFilter: testing.fn().mockRejectedValue(error),
    });
    const originalConsoleError = console.error;
    console.error = testing.fn();

    const downloadButton = setup(gmp);
    fireEvent.click(downloadButton);

    await wait();

    expect(showError).toHaveBeenCalledWith(error);
    expect(onDownloaded).not.toHaveBeenCalled();

    console.error = originalConsoleError;
  });

  test('should load tag-bulk choices through the native API when available', async () => {
    const getAllTags = testing.fn();
    const buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [{id: '1', name: 'Native tag', resource_type: 'port_list'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({
      buildUrl,
      getAllTags,
      session: {...createSession(), token: 'test-token'},
    });
    const tagButton = setupTagBulk(gmp);

    fireEvent.click(tagButton);
    await wait();

    expect(getAllTags).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith('api/v1/tags', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
      active: '',
      resource_type: 'port_list',
      value: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags',
      {
        credentials: 'include',
        headers: {Accept: 'application/json'},
      },
    );
  });

  test('should load selected tag detail through the native API when available', async () => {
    const getAllTags = testing.fn();
    const getTag = testing.fn();
    const buildUrl = testing.fn(
      (path: string) => `https://turbovas.example/${path}`,
    );
    const fetchMock = testing.fn((url: string) => {
      if (url.endsWith('/api/v1/tags')) {
        return Promise.resolve({
          json: testing.fn().mockResolvedValue({
            page: {page: 1, page_size: 25, total: 2, sort: 'name', filter: ''},
            items: [
              {id: '1', name: 'Native tag 1', resource_type: 'port_list'},
              {id: '2', name: 'Native tag 2', resource_type: 'port_list'},
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
            resource_type: 'port_list',
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
    const gmp = createGmp({
      buildUrl,
      getAllTags,
      getTag,
      session: {...createSession(), token: 'test-token'},
    });
    const tagButton = setupTagBulk(gmp);

    fireEvent.click(tagButton);
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
});

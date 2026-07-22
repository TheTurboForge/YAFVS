/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import FilterComponent from 'web/pages/filters/FilterComponent';
import {rendererWith, wait} from 'web/testing';

const nativeFilterPayload = {
  id: 'f123',
  name: 'test filter',
  comment: 'test comment',
  filter_type: 'task',
  term: 'rows=10 sort=name',
};

const mockFilter = Filter.fromElement({
  _id: 'f123',
  name: 'test filter',
  comment: 'test comment',
  type: 'task',
  term: 'rows=10 sort=name',
});

const stubNativeFetch = payload => {
  const fetchMock = testing.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: testing.fn().mockResolvedValue(payload),
  });
  testing.stubGlobal('fetch', fetchMock);
  return fetchMock;
};

const createGmp = ({
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  exportFilter = testing.fn().mockResolvedValue({
    data: '<filter id="f123"/>',
  }),
} = {}) => ({
  buildUrl: testing.fn((path, _params) => `https://yafvs.example/${path}`),
  session: {...createSession(), token: 'test-token', jwt: 'jwt-token'},
  user: {
    currentSettings,
  },
  filter: {
    export: exportFilter,
  },
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('FilterComponent tests', () => {
  test('should use native metadata export for downloads', async () => {
    const fetchMock = stubNativeFetch(nativeFilterPayload);
    let downloadClick;
    const children = testing.fn(({download}) => {
      downloadClick = download;
    });
    const onDownloaded = testing.fn();
    const onDownloadError = testing.fn();
    const gmp = createGmp({
      currentSettings: testing.fn().mockResolvedValue({
        data: {
          detailsexportfilename: {
            id: 'details-export-filename',
            name: 'Details Export File Name',
            value: '%T-%U',
          },
        },
      }),
    });

    const {render} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    render(
      <FilterComponent
        onDownloadError={onDownloadError}
        onDownloaded={onDownloaded}
      >
        {children}
      </FilterComponent>,
    );

    await wait();
    downloadClick(mockFilter);
    await wait();

    expect(gmp.filter.export).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/filters/f123/export', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(onDownloaded).toHaveBeenCalledWith({
      filename: 'filter-f123.json',
      data: `${JSON.stringify(nativeFilterPayload, null, 2)}\n`,
    });
    expect(onDownloadError).not.toHaveBeenCalled();
  });
});

/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {fireEvent, rendererWith, screen, wait, within} from 'web/testing';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import ReportFormatComponent from 'web/pages/reportformats/ReportFormatComponent';

const nativeReportFormatPayload = {
  id: 'rf123',
  name: 'test report format',
  summary: 'test summary',
  active: true,
  configurable: true,
  params: [
    {
      name: 'test param',
      type: 'string',
      value: 'ABC',
      default: 'ABC',
      min: 0,
      max: 100,
      options: [],
    },
  ],
};

const nativeReportFormatListParamPayload = {
  ...nativeReportFormatPayload,
  params: [
    {
      name: 'format choices',
      type: 'report_format_list',
      value: 'rf456',
      default: '',
      options: [],
    },
  ],
};

const nativeReportFormatsPayload = {
  page: {page: 1, page_size: 200, total: 1, sort: 'name', filter: ''},
  items: [
    {
      id: 'rf456',
      name: 'selectable report format',
      configurable: true,
      params: [],
    },
  ],
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

const createGmp = ({
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  getReportFormat = testing.fn().mockResolvedValue({data: {}}),
  getAllReportFormats = testing.fn().mockResolvedValue({data: []}),
  saveReportFormat = testing.fn().mockResolvedValue({data: {}}),
  importReportFormat = testing.fn().mockResolvedValue({data: {}}),
} = {}) => ({
  buildUrl: testing.fn((path, _params) => `https://turbovas.example/${path}`),
  session: {...createSession(), token: 'test-token', jwt: 'jwt-token'},
  user: {
    currentSettings,
  },
  reportformats: {
    getAll: getAllReportFormats,
  },
  reportformat: {
    get: getReportFormat,
    save: saveReportFormat,
    import: importReportFormat,
  },
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('Report Format Component tests', () => {
  test('should open edit dialog from native report format detail', async () => {
    const fetchMock = stubNativeFetch(nativeReportFormatPayload);
    let editClick;
    const children = testing.fn(({edit}) => {
      editClick = edit;
    });
    const gmp = createGmp();

    const {render} = rendererWith({
      gmp,
      router: true,
      store: true,
    });

    render(
      <ReportFormatComponent onImported={testing.fn()}>
        {children}
      </ReportFormatComponent>,
    );
    editClick({id: 'rf123'});

    await wait();

    expect(gmp.reportformat.get).not.toHaveBeenCalled();
    expect(gmp.reportformats.getAll).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-formats/rf123', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    expect(screen.queryDialogTitle()).toHaveTextContent(
      'Edit Report Format test report format',
    );
    const content = within(screen.queryDialogContent());
    const inputs = content.queryTextInputs();
    expect(inputs[0]).toHaveValue('test report format');

    const saveButton = screen.getDialogSaveButton();
    fireEvent.click(saveButton);

    expect(gmp.reportformat.save).toHaveBeenCalled();
  });

  test('should use native report format list when edit params require it', async () => {
    const fetchMock = stubNativeFetch(
      nativeReportFormatListParamPayload,
      nativeReportFormatsPayload,
    );
    let editClick;
    const children = testing.fn(({edit}) => {
      editClick = edit;
    });
    const gmp = createGmp();

    const {render} = rendererWith({
      gmp,
      router: true,
      store: true,
    });

    render(
      <ReportFormatComponent onImported={testing.fn()}>
        {children}
      </ReportFormatComponent>,
    );
    editClick({id: 'rf123'});

    await wait();

    expect(gmp.reportformat.get).not.toHaveBeenCalled();
    expect(gmp.reportformats.getAll).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-formats/rf123', {
      token: 'test-token',
    });
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-formats', {
      token: 'test-token',
      page: 1,
      page_size: 200,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    expect(screen.queryDialogContent()).toHaveTextContent('format choices');
    expect(screen.queryDialogContent()).toHaveTextContent(
      'selectable report format',
    );
  });

  test('should open import dialog without native reads', async () => {
    const fetchMock = stubNativeFetch();
    let importClick;
    const children = testing.fn(({import: openImport}) => {
      importClick = openImport;
    });
    const gmp = createGmp();

    const {render} = rendererWith({
      gmp,
      router: true,
      store: true,
    });

    render(
      <ReportFormatComponent onImported={testing.fn()}>
        {children}
      </ReportFormatComponent>,
    );
    importClick();

    await wait();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(gmp.reportformat.get).not.toHaveBeenCalled();
    expect(gmp.reportformats.getAll).not.toHaveBeenCalled();
    expect(screen.queryDialogTitle()).toHaveTextContent('Import Report Format');
  });
});

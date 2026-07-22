/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fireEvent, rendererWith, screen} from 'web/testing';
import {createActionResultResponse} from 'gmp/commands/testing';
import Response from 'gmp/http/response';
import {createSession} from 'gmp/testing';
import {DEFAULT_SEVERITY_RATING} from 'gmp/utils/severity';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import OverrideComponent from 'web/pages/overrides/OverrideComponent';

const createGmp = ({
  buildUrl,
  getAllTasks = testing.fn().mockResolvedValue(new Response([])),
  session = createSession(),
} = {}) => ({
  buildUrl,
  override: {
    clone: testing
      .fn()
      .mockResolvedValue(createActionResultResponse({id: 'cloned-id'})),
    create: testing
      .fn()
      .mockResolvedValue(createActionResultResponse({id: 'created-id'})),
    delete: testing.fn().mockResolvedValue(new Response('deleted')),
    export: testing.fn().mockResolvedValue(new Response('exported')),
    save: testing
      .fn()
      .mockResolvedValue(createActionResultResponse({id: 'saved-id'})),
  },
  session,
  settings: {
    severityRating: DEFAULT_SEVERITY_RATING,
  },
  tasks: {
    getAll: getAllTasks,
  },
  user: {
    currentSettings: testing
      .fn()
      .mockResolvedValue(currentSettingsDefaultResponse),
  },
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('OverrideComponent tests', () => {
  test('should load task choices through the native API when available', async () => {
    const getAllTasks = testing.fn();
    const buildUrl = testing.fn(
      (path, _params) => `https://yafvs.example/${path}`,
    );
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 200, total: 1, sort: 'name', filter: ''},
        items: [{id: 'task-1', name: 'Native task', status: 'Done'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({
      buildUrl,
      getAllTasks,
      session: createSession({token: 'test-token'}),
    });
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <OverrideComponent>
        {({create}) => (
          <button data-testid="button" onClick={() => create()}>
            Create override
          </button>
        )}
      </OverrideComponent>,
    );

    fireEvent.click(screen.getByTestId('button'));

    await screen.findByText('New Override');

    expect(getAllTasks).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith('api/v1/tasks', {
      token: 'test-token',
      page: 1,
      page_size: 200,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/tasks',
      {
        credentials: 'include',
        headers: {Accept: 'application/json'},
      },
    );
  });
});

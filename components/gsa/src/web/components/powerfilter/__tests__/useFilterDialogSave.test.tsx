/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {rendererWith} from 'web/testing';
import Filter from 'gmp/models/filter';
import useFilterDialogSave from 'web/components/powerfilter/useFilterDialogSave';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('useFilterDialogSave', () => {
  test('should create a named filter and keep the entered name', async () => {
    const create = testing.fn().mockResolvedValue({data: {id: '123'}});
    const createdFilter = Filter.fromElement({_id: '123', term: 'foo=bar'});
    const get = testing.fn().mockResolvedValue({data: createdFilter});
    const onFilterCreated = testing.fn();
    const onClose = testing.fn();

    const {renderHook} = rendererWith({
      gmp: {
        filter: {
          create,
          get,
        },
      },
    });

    const {result} = renderHook(() =>
      useFilterDialogSave(
        'result',
        {onClose, onFilterCreated},
        {
          filterName: '  My Filter  ',
          saveNamedFilter: true,
          filter: Filter.fromString('foo=bar'),
          filterString: 'rows=10',
          originalFilter: Filter.fromString('foo=bar'),
        },
      ),
    );

    await result.current.handleSave();

    expect(create).toHaveBeenCalledWith({
      term: 'foo=bar rows=10',
      type: 'result',
      name: '  My Filter  ',
    });
    expect(get).toHaveBeenCalledWith({id: '123'});
    expect(onFilterCreated).toHaveBeenCalledWith(createdFilter);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('should load a newly created named filter through native API when available', async () => {
    const create = testing.fn().mockResolvedValue({data: {id: '123'}});
    const get = testing.fn();
    const buildUrl = testing.fn(
      path => `https://turbovas.example/${String(path)}`,
    );
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '123',
        name: 'My Filter',
        filter_type: 'result',
        term: 'foo=bar rows=10',
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const onFilterCreated = testing.fn();

    const {renderHook} = rendererWith({
      gmp: {
        buildUrl,
        session: {jwt: 'jwt-token', token: 'session-token'},
        filter: {
          create,
          get,
        },
      },
    });

    const {result} = renderHook(() =>
      useFilterDialogSave(
        'result',
        {onFilterCreated},
        {
          filterName: 'My Filter',
          saveNamedFilter: true,
          filter: Filter.fromString('foo=bar'),
          filterString: 'rows=10',
          originalFilter: Filter.fromString('foo=bar'),
        },
      ),
    );

    await result.current.handleSave();

    expect(get).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith('api/v1/filters/123', {
      token: 'session-token',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters/123',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(onFilterCreated).toHaveBeenCalledWith(
      expect.objectContaining({id: '123'}),
    );
  });

  test('should reject save when creating named filter without a valid name', async () => {
    const create = testing.fn();

    const {renderHook} = rendererWith({
      gmp: {
        filter: {
          create,
          get: testing.fn(),
        },
      },
    });

    const {result} = renderHook(() =>
      useFilterDialogSave(
        'result',
        {},
        {
          filterName: '   ',
          saveNamedFilter: true,
          filter: Filter.fromString('foo=bar'),
          filterString: 'rows=10',
          originalFilter: Filter.fromString('foo=bar'),
        },
      ),
    );

    await expect(result.current.handleSave()).rejects.toThrow(
      'Please insert a name for the new filter',
    );
    expect(create).not.toHaveBeenCalled();
  });
});

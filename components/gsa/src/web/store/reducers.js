/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {combineReducers} from 'redux';
import {CLEAR_STORE} from 'web/store/actions';
import entities from 'web/store/entities/reducers';
import feedStatus from 'web/store/feedStatus/reducers';
import pages from 'web/store/pages/reducers';
import userSettings from 'web/store/usersettings/reducers';

const rootReducer = combineReducers({
  entities,
  userSettings,
  pages,
  feedStatus,
});

const clearStoreReducer = (state = {}, action) => {
  if (action.type === CLEAR_STORE) {
    state = {};
  }
  return rootReducer(state, action);
};

export default clearStoreReducer;

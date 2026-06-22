/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, beforeEach} from '@gsa/testing';
import {
  saveLastVisitedPage,
  getLastVisitedPage,
  clearLastVisitedPage,
} from 'web/utils/user-last-visited-page';

describe('user-last-visited-page utils', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  describe('saveLastVisitedPage', () => {
    test('should save last visited page for a user', () => {
      saveLastVisitedPage('user1', '/tasks');

      expect(sessionStorage.getItem('gsa_last_visited_page_user1')).toBe(
        '/tasks',
      );
    });

    test('should save different paths for different users', () => {
      saveLastVisitedPage('user1', '/tasks');
      saveLastVisitedPage('user2', '/reports');

      expect(sessionStorage.getItem('gsa_last_visited_page_user1')).toBe(
        '/tasks',
      );
      expect(sessionStorage.getItem('gsa_last_visited_page_user2')).toBe(
        '/reports',
      );
    });

    test('should handle path with search and hash', () => {
      saveLastVisitedPage('user1', '/tasks?filter=all#top');

      expect(sessionStorage.getItem('gsa_last_visited_page_user1')).toBe(
        '/tasks?filter=all#top',
      );
    });

    test('should not save if username is empty', () => {
      saveLastVisitedPage('', '/tasks');

      expect(sessionStorage.getItem('gsa_last_visited_page_')).toBeNull();
    });

    test('should not save if path is empty', () => {
      saveLastVisitedPage('user1', '');

      expect(sessionStorage.getItem('gsa_last_visited_page_user1')).toBeNull();
    });

    test('should overwrite previous path for same user', () => {
      saveLastVisitedPage('user1', '/tasks');
      saveLastVisitedPage('user1', '/reports');

      expect(sessionStorage.getItem('gsa_last_visited_page_user1')).toBe(
        '/reports',
      );
    });
  });

  describe('getLastVisitedPage', () => {
    test('should retrieve last visited page for a user', () => {
      sessionStorage.setItem('gsa_last_visited_page_user1', '/tasks');

      const result = getLastVisitedPage('user1');

      expect(result).toBe('/tasks');
    });

    test('should return undefined if no page saved for user', () => {
      const result = getLastVisitedPage('user1');

      expect(result).toBeUndefined();
    });

    test('should return undefined if username is empty', () => {
      const result = getLastVisitedPage('');

      expect(result).toBeUndefined();
    });

    test('should retrieve correct path for specific user', () => {
      sessionStorage.setItem('gsa_last_visited_page_user1', '/tasks');
      sessionStorage.setItem('gsa_last_visited_page_user2', '/reports');

      const result1 = getLastVisitedPage('user1');
      const result2 = getLastVisitedPage('user2');

      expect(result1).toBe('/tasks');
      expect(result2).toBe('/reports');
    });
  });

  describe('clearLastVisitedPage', () => {
    test('should clear last visited page for a user', () => {
      sessionStorage.setItem('gsa_last_visited_page_user1', '/tasks');

      clearLastVisitedPage('user1');

      expect(sessionStorage.getItem('gsa_last_visited_page_user1')).toBeNull();
    });

    test('should only clear for specific user', () => {
      sessionStorage.setItem('gsa_last_visited_page_user1', '/tasks');
      sessionStorage.setItem('gsa_last_visited_page_user2', '/reports');

      clearLastVisitedPage('user1');

      expect(sessionStorage.getItem('gsa_last_visited_page_user1')).toBeNull();
      expect(sessionStorage.getItem('gsa_last_visited_page_user2')).toBe(
        '/reports',
      );
    });

    test('should handle clearing non-existent entry', () => {
      expect(() => clearLastVisitedPage('user1')).not.toThrow();
    });

    test('should not clear if username is empty', () => {
      sessionStorage.setItem('gsa_last_visited_page_', '/tasks');

      clearLastVisitedPage('');

      expect(sessionStorage.getItem('gsa_last_visited_page_')).toBe('/tasks');
    });
  });

  describe('integration scenarios', () => {
    test('should handle complete user flow', () => {
      // User1 logs out from /tasks
      saveLastVisitedPage('user1', '/tasks?filter=open');

      // User2 logs out from /reports
      saveLastVisitedPage('user2', '/reports');

      // User1 logs back in
      const user1Path = getLastVisitedPage('user1');
      expect(user1Path).toBe('/tasks?filter=open');
      clearLastVisitedPage('user1');

      // User2 logs back in
      const user2Path = getLastVisitedPage('user2');
      expect(user2Path).toBe('/reports');
      clearLastVisitedPage('user2');

      // Both should be cleared now
      expect(getLastVisitedPage('user1')).toBeUndefined();
      expect(getLastVisitedPage('user2')).toBeUndefined();
    });
  });
});

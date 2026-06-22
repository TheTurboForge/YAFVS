/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {type EntityActionResponse} from 'gmp/commands/entity';
import {type EntitiesMeta} from 'gmp/commands/entities';
import type Rejection from 'gmp/http/rejection';
import Response from 'gmp/http/response';
import {type XmlMeta, type XmlResponseData} from 'gmp/http/transform/fast-xml';
import Filter, {ALL_FILTER} from 'gmp/models/filter';
import {isFilter} from 'gmp/models/filter/utils';
import type Tag from 'gmp/models/tag';
import {
  fetchNativeTag,
  fetchNativeTags,
  nativeTagsQueryFromFilter,
} from 'gmp/native-api/tags';
import useGmp from 'web/hooks/useGmp';
import type {RefetchIntervalFn} from 'web/queries/helpers';
import useCloneMutation from 'web/queries/useCloneMutation';
import useCreateMutation from 'web/queries/useCreateMutation';
import useDeleteMutation from 'web/queries/useDeleteMutation';
import useGetEntities from 'web/queries/useGetEntities';
import useGetEntity from 'web/queries/useGetEntity';
import useGmpMutation from 'web/queries/useGmpMutation';
import useSaveMutation from 'web/queries/useSaveMutation';

interface UseGetTagParams {
  id: string;
  refetchInterval?: RefetchIntervalFn<Tag>;
}

interface UseGetTagsParams {
  filter?: Filter;
}

interface UseMutationCallbacks {
  onSuccess?: () => void;
  onError?: (error: Rejection) => void;
}

interface UseCreateTagParams {
  onSuccess?: (data: EntityActionResponse) => void;
  onError?: (error: Error) => void;
}

interface UseModifyTagParams {
  onSuccess?: () => void;
  onError?: (error: Error) => void;
}

type TagBulkInput = Tag[] | Filter;

const canUseNativeApi = (gmp: {buildUrl?: unknown}) =>
  typeof gmp?.buildUrl === 'function';

export const useGetTags = ({filter}: UseGetTagsParams) => {
  const gmp = useGmp();
  return useGetEntities<Tag>({
    gmpMethod: async () => {
      if (!canUseNativeApi(gmp)) {
        return gmp.tags.get({filter});
      }
      const nativeResponse = await fetchNativeTags(
        gmp,
        nativeTagsQueryFromFilter(filter),
      );
      return new Response<Tag[], EntitiesMeta>(nativeResponse.tags, {
        counts: nativeResponse.counts,
        filter: filter ?? ALL_FILTER,
      });
    },
    queryId: 'get_tags',
    filter,
  });
};

export const useGetTag = ({id, refetchInterval}: UseGetTagParams) => {
  const gmp = useGmp();
  return useGetEntity<Tag>({
    gmpMethod: async ({id}) => {
      if (!canUseNativeApi(gmp)) {
        return gmp.tag.get({id});
      }
      return new Response<Tag, XmlMeta>(await fetchNativeTag(gmp, id));
    },
    queryId: 'get_tag',
    id,
    refetchInterval,
  });
};

export const useDeleteTag = ({onError, onSuccess}: UseMutationCallbacks) => {
  const gmp = useGmp();
  return useDeleteMutation<void, Rejection>({
    entityType: 'tag',
    gmpMethod: ({id}) => gmp.tag.delete({id}),
    invalidateQueryIds: ['get_tags'],
    onSuccess,
    onError,
  });
};

export const useEnableTag = ({
  onError,
  onSuccess,
}: UseMutationCallbacks = {}) => {
  const gmp = useGmp();
  return useGmpMutation<
    {id: string},
    Response<XmlResponseData, XmlMeta>,
    Rejection
  >({
    gmpMethod: ({id}) => gmp.tag.enable({id}),
    invalidateQueryIds: ['get_tags'],
    onSuccess,
    onError,
  });
};

export const useDisableTag = ({
  onError,
  onSuccess,
}: UseMutationCallbacks = {}) => {
  const gmp = useGmp();
  return useGmpMutation<
    {id: string},
    Response<XmlResponseData, XmlMeta>,
    Rejection
  >({
    gmpMethod: ({id}) => gmp.tag.disable({id}),
    invalidateQueryIds: ['get_tags'],
    onSuccess,
    onError,
  });
};

export const useBulkDeleteTags = ({
  onError,
  onSuccess,
}: UseMutationCallbacks) => {
  const gmp = useGmp();
  return useGmpMutation<TagBulkInput, Response<Tag[], XmlMeta>, Rejection>({
    gmpMethod: (input: TagBulkInput) => {
      return isFilter(input)
        ? gmp.tags.deleteByFilter(input)
        : gmp.tags.delete(input);
    },
    invalidateQueryIds: ['get_tags'],
    onSuccess,
    onError,
  });
};

export const useBulkExportTags = ({
  onError,
  onSuccess,
}: UseMutationCallbacks) => {
  const gmp = useGmp();
  return useGmpMutation<TagBulkInput, Response<string>, Rejection>({
    gmpMethod: (input: TagBulkInput) => {
      return isFilter(input)
        ? gmp.tags.exportByFilter(input)
        : gmp.tags.export(input);
    },
    onSuccess,
    onError,
  });
};

export const useCreateTag = ({onSuccess, onError}: UseCreateTagParams) => {
  const gmp = useGmp();
  return useCreateMutation<
    Parameters<typeof gmp.tag.create>[0],
    EntityActionResponse,
    Rejection
  >({
    entityType: 'tag',
    gmpMethod: input => gmp.tag.create(input),
    invalidateQueryIds: ['get_tags'],
    onError,
    onSuccess,
  });
};

export const useSaveTag = ({onError, onSuccess}: UseModifyTagParams) => {
  const gmp = useGmp();
  return useSaveMutation<
    Parameters<typeof gmp.tag.save>[0],
    EntityActionResponse,
    Rejection
  >({
    entityType: 'tag',
    gmpMethod: input => gmp.tag.save(input),
    invalidateQueryIds: ['get_tags'],
    onError,
    onSuccess,
  });
};

export const useCloneTag = ({onSuccess, onError}: UseCreateTagParams) => {
  const gmp = useGmp();
  return useCloneMutation<EntityActionResponse, Rejection>({
    entityType: 'tag',
    gmpMethod: ({id}) => gmp.tag.clone({id}),
    invalidateQueryIds: ['get_tags'],
    onError,
    onSuccess,
  });
};

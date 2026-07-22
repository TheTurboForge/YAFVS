/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useCallback, useEffect, useState} from 'react';
import type CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import type Model from 'gmp/models/model';
import Tag from 'gmp/models/tag';
import {nativeTagResourceSelectionFromFilter} from 'gmp/native-api/tag-resource-selection';
import {
  fetchNativeTag,
  fetchNativeTags,
  nativeTagsQueryFromFilter,
  type NativeTagResourceSelectionInput,
} from 'gmp/native-api/tags';
import {apiType, type EntityType, getEntityType} from 'gmp/utils/entity-type';
import {isDefined} from 'gmp/utils/identity';
import TagsDialog, {type TagsDialogData} from 'web/entities/TagsDialog';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import TagDialog, {type TagDialogState} from 'web/pages/tags/TagDialog';
import SelectionType, {type SelectionTypeType} from 'web/utils/SelectionType';

interface BulkTagsProps<TEntity extends Model> {
  entities: TEntity[];
  selectedEntities: TEntity[];
  filter: Filter;
  selectionType: SelectionTypeType;
  entitiesCounts: CollectionCounts;
  onClose: () => void;
}

const getEntityIds = <TEntity extends Model>(entityArray: TEntity[] = []) =>
  entityArray.map(entity => entity.id as string);

const canUseNativeApi = (gmp: {buildUrl?: unknown}) =>
  typeof gmp?.buildUrl === 'function';

const tagIdFromResponse = (data: unknown): string =>
  typeof data === 'string'
    ? data
    : String((data as {id?: string | number})?.id ?? '');

const loadTag = (gmp: ReturnType<typeof useGmp>, data: unknown) => {
  const id = tagIdFromResponse(data);
  if (canUseNativeApi(gmp) && id.length > 0) {
    return fetchNativeTag(gmp, id);
  }
  const params = (typeof data === 'string' ? {id: data} : data) as Parameters<
    typeof gmp.tag.get
  >[0];
  return gmp.tag.get(params).then(resp => resp.data);
};

const getMultiTagEntitiesCount = <TEntity extends Model>(
  pageEntities: TEntity[],
  counts: CollectionCounts,
  selectedEntities: TEntity[] | Set<TEntity>,
  selectionType: SelectionTypeType,
) => {
  if (selectionType === SelectionType.SELECTION_USER) {
    // support set and array
    return isDefined((selectedEntities as Set<TEntity>)?.size)
      ? (selectedEntities as Set<TEntity>).size
      : (selectedEntities as TEntity[]).length;
  }

  if (selectionType === SelectionType.SELECTION_PAGE_CONTENTS) {
    return pageEntities.length;
  }

  return counts.filtered;
};

const BulkTags = <TEntity extends Model>({
  entities,
  selectedEntities,
  filter,
  selectionType,
  entitiesCounts,
  onClose,
}: BulkTagsProps<TEntity>) => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const [tag, setTag] = useState<Tag>(new Tag());
  const [tagDialogVisible, setTagDialogVisible] = useState(false);
  const [tags, setTags] = useState<Tag[]>([]);
  const [error, setError] = useState();

  const entitiesType = getEntityType(entities[0]);
  // if there are no entities, BulkTagComponent is not rendered.

  const fetchTagsByType = useCallback(() => {
    const tagFilter = `resource_type=${apiType(entitiesType)}`;
    if (canUseNativeApi(gmp)) {
      const filter = Filter.fromString(tagFilter);
      return fetchNativeTags(gmp, nativeTagsQueryFromFilter(filter))
        .then(({tags}) => {
          setTags(tags);
        })
        .catch(setError);
    }
    return gmp.tags
      .getAll({filter: tagFilter})
      .then(resp => {
        setTags(resp.data);
      })
      .catch(setError);
  }, [gmp, entitiesType]);

  useEffect(() => {
    void fetchTagsByType();
  }, [fetchTagsByType]);

  const multiTagEntitiesCount = getMultiTagEntitiesCount(
    entities,
    entitiesCounts,
    selectedEntities,
    selectionType,
  );

  const closeTagDialog = useCallback(() => {
    setTagDialogVisible(false);
  }, []);

  const openTagDialog = useCallback(() => {
    setTagDialogVisible(true);
  }, []);

  const handleCreateTag = useCallback(
    (data: TagDialogState) => {
      return gmp.tag
        .create({
          active: data.active,
          comment: data.comment,
          name: data.name as string,
          resourceIds: data.resourceIds,
          resourceType: data.resourceType as EntityType,
          value: data.value as string,
        })
        .then(response => loadTag(gmp, response.data))
        .then(tag => {
          const newTags = [...tags, tag];
          setTags(newTags);
          setTag(tag);
        })
        .then(closeTagDialog)
        .catch(setError);
    },
    [closeTagDialog, gmp, tags],
  );

  const handleCloseTagDialog = useCallback(() => {
    closeTagDialog();
  }, [closeTagDialog]);

  const handleTagChange = useCallback(
    (id: string) => {
      return loadTag(gmp, id)
        .then(tag => {
          setTag(tag);
        })
        .catch(setError);
    },
    [gmp],
  );

  const handleCloseTagsDialog = useCallback(() => {
    onClose();
  }, [onClose]);

  const handleErrorClose = useCallback(() => {
    setError(undefined);
  }, []);

  const handleAddMultiTag = useCallback(
    ({comment, id, name, value = ''}: TagsDialogData) => {
      let tagEntitiesIds: string[] | undefined = undefined;
      let loadedFilter: string | undefined = undefined;
      let resourceSelection: NativeTagResourceSelectionInput | undefined =
        undefined;

      if (selectionType === SelectionType.SELECTION_USER) {
        tagEntitiesIds = getEntityIds(selectedEntities);
      } else if (selectionType === SelectionType.SELECTION_PAGE_CONTENTS) {
        tagEntitiesIds = getEntityIds(entities);
      } else {
        try {
          resourceSelection = nativeTagResourceSelectionFromFilter(
            entitiesType,
            filter,
            entitiesCounts.filtered,
          );
        } catch (error) {
          return Promise.reject(error);
        }
        if (resourceSelection === undefined) {
          loadedFilter = filter.all().toFilterString();
        }
      }

      return gmp.tag
        .save({
          active: true,
          comment,
          filter: loadedFilter,
          id: id as string,
          name: name as string,
          resourceIds: tagEntitiesIds,
          resourceSelection,
          resourceType: entitiesType,
          resourcesAction: 'add',
          value,
        })
        .then(onClose)
        .catch(setError);
    },
    [
      entities,
      entitiesCounts.filtered,
      entitiesType,
      filter,
      gmp.tag,
      onClose,
      selectedEntities,
      selectionType,
    ],
  );

  const resourceTypes = [entitiesType];

  let title: string;
  if (selectionType === SelectionType.SELECTION_USER) {
    title = _('Add Tag to Selection');
  } else if (selectionType === SelectionType.SELECTION_PAGE_CONTENTS) {
    title = _('Add Tag to Page Contents');
  } else {
    title = _('Add Tag to All Filtered');
  }

  return (
    <>
      <TagsDialog
        comment={tag.comment}
        entitiesCount={multiTagEntitiesCount}
        error={error}
        name={tag.name}
        tagId={tag.id}
        tags={tags}
        title={title}
        value={tag.value}
        onClose={handleCloseTagsDialog}
        onErrorClose={handleErrorClose}
        onNewTagClick={openTagDialog}
        onSave={handleAddMultiTag}
        onTagChanged={handleTagChange}
      />
      {tagDialogVisible && (
        <TagDialog
          fixed={true}
          resourceIds={selectedEntities.map(entity => entity.id as string)}
          resourceType={entitiesType}
          resourceTypes={resourceTypes}
          onClose={handleCloseTagDialog}
          onSave={handleCreateTag}
        />
      )}
    </>
  );
};

export default BulkTags;

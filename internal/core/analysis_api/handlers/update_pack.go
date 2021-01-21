package handlers

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) PatchPack(input *models.PatchPackInput) *events.APIGatewayProxyResponse {
	// This is a partial update, so lookup existing item values
	var item *packTableItem
	item, err := dynamoGetPack(input.ID, false)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Internal error finding %s (%s)", input.ID, models.TypePack),
			StatusCode: http.StatusInternalServerError,
		}
	}
	if item == nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Cannot find %s (%s)", input.ID, models.TypePack),
			StatusCode: http.StatusNotFound,
		}
	}
	// Update the enabled status and enabledRelease if it has changed
	// Note: currently only support `enabled` and `enabledRelease` updates from the `patch` operation
	if input.EnabledVersion.Name != "" && input.EnabledVersion.Name != item.EnabledVersion.Name {
		// updating the enabled version
		return updatePackEnabledVersion(input, item)
	} else if input.Enabled != item.Enabled {
		// Otherwise, we are simply updating the enablement status of the pack and the
		// detections in this pack.
		return updatePackEnablement(input, item)
	}
	// Nothing to update, report success
	return gatewayapi.MarshalResponse(item.Pack(), http.StatusOK)
}

func updatePackEnabledVersion(input *models.PatchPackInput, item *packTableItem) *events.APIGatewayProxyResponse {
	// First, update the pack metadata in case the detection pattern has been updated
	err := updatePackToVersion(input, item)
	if err != nil {
		zap.L().Error("Error updating pack metadata", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	// get new version of the pack
	newPack, err := dynamoGetPack(input.ID, false)
	if err != nil {
		zap.L().Error("Error getting pack", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	// Then, update the detections in the pack
	err = updatePackDetections(input.UserID, newPack, input.EnabledVersion)
	if err != nil {
		// TODO: do we need to attempt to rollback the update if the pack detection update fails?
		zap.L().Error("Error updating pack detections", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	// return success
	return gatewayapi.MarshalResponse(newPack.Pack(), http.StatusOK)
}

func updatePackEnablement(input *models.PatchPackInput, item *packTableItem) *events.APIGatewayProxyResponse {
	// The detection list has not changed, get the current list
	detections, err := detectionLookup(item.DetectionPattern)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	// Update the enabled status for the detections in this pack
	for i, detection := range detections {
		if detection.Enabled != input.Enabled {
			detection.Enabled = input.Enabled
			_, err = writeItem(detections[i], input.UserID, aws.Bool(true))
			if err != nil {
				return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
			}
		}
	}
	// Then, Update the enablement status of the pack itself
	item.Enabled = input.Enabled
	err = updatePack(item, input.UserID)
	if err != nil {
		zap.L().Error("Error updating pack enabled status", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	// return success
	return gatewayapi.MarshalResponse(item.Pack(), http.StatusOK)
}

func updatePack(item *packTableItem, userID string) error {
	// ensure the correct type is set
	item.Type = models.TypePack
	if err := writePack(item, userID, nil); err != nil {
		return err
	}
	return nil
}

func updatePackDetections(userID string, pack *packTableItem, release models.Version) error {
	newDetectionItems, err := setupUpdatePackDetections(pack, release)
	if err != nil {
		return err
	}
	for _, newDetectionItem := range newDetectionItems {
		_, err = writeItem(newDetectionItem, userID, aws.Bool(true))
		if err != nil {
			// TODO: should we try to rollback the other updated detections?
			return err
		}
	}
	return nil
}

func setupUpdatePackDetections(pack *packTableItem, version models.Version) ([]*tableItem, error) {
	// setup slice to return
	var newItems []*tableItem
	// check the pack & detection cache
	if time.Since(cacheLastUpdated) > cacheTimeout || cacheVersion.ID != version.ID {
		// cache has timed out or cache has wrong detection version
		// Retrieve new version of detections
		err := downloadValidatePackData(version)
		if err != nil {
			return nil, err
		}
	}
	// First lookup the existing detections in this pack
	detections, err := detectionLookup(pack.DetectionPattern)
	if err != nil {
		return nil, err
	}
	// Then get a list of the updated detection in the pack
	newDetections := detectionCacheLookup(pack.DetectionPattern)
	if err != nil {
		return nil, err
	}
	// Loop through the new detections and update appropriate fields or
	//  create new detection
	for id, newDetection := range newDetections {
		if detection, ok := detections[id]; ok {
			// update existing detection
			// TODO: decide if the commented out things should be preserved / not overwritten
			detection.Body = newDetection.Body
			// detection.DedupPeriodMinutes = newDetection.DedupPeriodMinutes
			detection.Description = newDetection.Description
			detection.DisplayName = newDetection.DisplayName
			detection.Enabled = pack.Enabled
			detection.ResourceTypes = newDetection.ResourceTypes // aka LogTypes
			// detection.OutputIDs = newDetection.OutputIDs
			detection.Reference = newDetection.Reference
			detection.Reports = newDetection.Reports
			detection.Runbook = newDetection.Runbook
			// detection.Severity = newDetection.Severity
			detection.Tags = newDetection.Tags
			detection.Tests = newDetection.Tests
			// detection.Threshold = newDetection.Threshold
			newItems = append(newItems, detection)
		} else {
			// create new detection
			newItems = append(newItems, newDetection)
		}
	}
	return newItems, nil
}

func updatePackVersions(newVersion models.Version, oldPacks []*packTableItem) error {
	newPacks, err := setupUpdatePacksVersions(newVersion, oldPacks)
	if err != nil {
		return err
	}
	for _, newPack := range newPacks {
		// TODO: Is it ok to keep the previous user id of the person that modified it?
		// or should this be the "system" userid?
		if err = updatePack(newPack, newPack.LastModifiedBy); err != nil {
			return err
		}
	}
	return nil
}

func setupUpdatePacksVersions(newVersion models.Version, oldPacks []*packTableItem) ([]*packTableItem, error) {
	// setup var to return slice of updated pack items
	var newPackItems []*packTableItem
	// check the cache for fresh data
	if time.Since(cacheLastUpdated) > cacheTimeout || cacheVersion.ID != newVersion.ID {
		// cache has timed out or cache has wrong detection version
		// Retrieve new version of detections
		err := downloadValidatePackData(newVersion)
		if err != nil {
			return nil, err
		}
	}
	oldPacksMap := make(map[string]*packTableItem)
	// convert oldPacks to a map for ease of comparison
	for _, oldPack := range oldPacks {
		oldPacksMap[oldPack.ID] = oldPack
	}
	// Loop through new packs. Old/deprecated packs will simply not get updated
	for id, newPack := range packCache {
		if oldPack, ok := oldPacksMap[id]; ok {
			// Update existing pack metadata fields: AvailableVersions and UpdateAvailable
			if !containsRelease(oldPack.AvailableVersions, newVersion) {
				// only add the new version to the availableVersions if it is not already there
				oldPack.AvailableVersions = append(oldPack.AvailableVersions, newVersion)
				oldPack.UpdateAvailable = true
				newPackItems = append(newPackItems, oldPack)
			} else {
				// the pack already knows about this version, just continue
				continue
			}
		} else {
			// Add a new pack, and auto-disable it. AvailableVersionss will only
			// contain the version where it was added
			newPack.Enabled = false
			newPack.AvailableVersions = []models.Version{newVersion}
			newPack.UpdateAvailable = true
			newPack.EnabledVersion = newVersion
			newPack.LastModifiedBy = systemUserID
			newPack.CreatedBy = systemUserID
			newPackItems = append(newPackItems, newPack)
		}
	}
	return newPackItems, nil
}

func updatePackToVersion(input *models.PatchPackInput, item *packTableItem) error {
	newPack, err := setupUpdatePackToVersion(input, item)
	if err != nil {
		zap.L().Error("Error setting up pack version fields",
			zap.String("newVersion", input.EnabledVersion.Name))
		return err
	}
	return updatePack(newPack, input.UserID)
}

func setupUpdatePackToVersion(input *models.PatchPackInput, oldPack *packTableItem) (*packTableItem, error) {
	version := input.EnabledVersion
	// check the pack & detection cache
	if time.Since(cacheLastUpdated) > cacheTimeout || cacheVersion.ID != version.ID {
		// cache has timed out or cache has wrong detection version
		// Retrieve new version of detections
		err := downloadValidatePackData(version)
		if err != nil {
			return nil, err
		}
	}
	if newPack, ok := packCache[input.ID]; ok {
		updateAvailable := isNewReleaseAvailable(version, []*packTableItem{oldPack})
		pack := &packTableItem{
			Enabled:           input.Enabled, // update the item enablement status if it has been updated
			UpdateAvailable:   updateAvailable,
			Description:       newPack.Description,
			DetectionPattern:  newPack.DetectionPattern,
			DisplayName:       newPack.DisplayName,
			EnabledVersion:    version,
			ID:                input.ID,
			AvailableVersions: oldPack.AvailableVersions,
		}
		return pack, nil
	}
	// This is a deprecated / delete pack - it got to this point in error
	zap.L().Error("Trying to update a deprecated pack",
		zap.String("pack", input.ID),
		zap.String("version", version.Name))
	return nil, nil
}

func detectionLookup(input models.DetectionPattern) (map[string]*tableItem, error) {
	items := make(map[string]*tableItem)

	var filters []expression.ConditionBuilder

	// Currently only support specifying IDs
	if len(input.IDs) > 0 {
		idFilter := expression.AttributeNotExists(expression.Name("lowerId"))
		for _, id := range input.IDs {
			idFilter = idFilter.Or(expression.Contains(expression.Name("lowerId"), strings.ToLower(id)))
		}
		filters = append(filters, idFilter)
	}

	// Build the scan input
	// include all detection types
	scanInput, err := buildScanInput(
		[]models.DetectionType{
			models.TypeRule,
			models.TypePolicy,
			models.TypeDataModel,
			models.TypeGlobal,
		},
		[]string{},
		filters...)
	if err != nil {
		return nil, err
	}

	// scan for all detections
	err = scanPages(scanInput, func(item tableItem) error {
		items[item.ID] = &item
		return nil
	})
	if err != nil {
		zap.L().Error("failed to scan detections", zap.Error(err))
		return nil, err
	}

	return items, nil
}

func detectionCacheLookup(input models.DetectionPattern) map[string]*tableItem {
	items := make(map[string]*tableItem)

	// Currently only support specifying IDs
	if len(input.IDs) > 0 {
		for _, id := range input.IDs {
			if detection, ok := detectionCache[id]; ok {
				items[detection.ID] = detection
			} else {
				zap.L().Warn("attempted to add detection that does not exist",
					zap.String("detectionId", id))
			}
		}
	}

	return items
}

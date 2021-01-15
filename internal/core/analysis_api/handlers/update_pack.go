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
	if input.EnabledRelease.Version != item.EnabledRelease.Version {
		// update the item enabledment status if it has been updated
		if input.Enabled != item.Enabled {
			item.Enabled = input.Enabled
		}
		// First, update the pack metadata in case the detection pattern has been updated
		err = updatePackMetadata(input.UserID, item, input.EnabledRelease)
		if err != nil {
			zap.L().Error("Error updating pack metadata", zap.Error(err))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		// get new version of the pack
		item, err := dynamoGetPack(input.ID, false)
		// Then, update the detections in the pack
		err = updatePackDetections(input.UserID, item, input.EnabledRelease)
		if err != nil {
			// TODO: do we need to attempt to rollback the update if the pack detection update fails?
			zap.L().Error("Error updating pack detections", zap.Error(err))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
	} else if input.Enabled != item.Enabled {
		// Otherwise, we are simply updating the enablement status of the detections
		// in this pack. The detection list has not changed, get the current list
		detections, err := detectionLookup(item.DetectionPattern)
		if err != nil {
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
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
		updateInput := models.UpdatePackInput{
			Description:      item.Description,
			DetectionPattern: item.DetectionPattern,
			DisplayName:      item.DisplayName,
			Enabled:          input.Enabled,
			EnabledRelease:   item.EnabledRelease,
			UpdateAvailable:  item.UpdateAvailable,
			UserID:           input.UserID,
		}
		return updatePack(&updateInput, false)
	}
	// Nothing to update, report success
	return gatewayapi.MarshalResponse(item.Pack(), http.StatusOK)
}

func updatePack(input *models.UpdatePackInput, create bool) *events.APIGatewayProxyResponse {
	item := &packTableItem{
		AvailableReleases: input.AvailableReleases,
		Description:       input.Description,
		DetectionPattern:  input.DetectionPattern,
		DisplayName:       input.DisplayName,
		Enabled:           input.Enabled,
		EnabledRelease:    input.EnabledRelease,
		UpdateAvailable:   input.UpdateAvailable,
	}

	var statusCode int

	if create {
		if err := writePack(item, input.UserID, aws.Bool(false)); err != nil {
			if err == errExists {
				return &events.APIGatewayProxyResponse{
					Body:       err.Error(),
					StatusCode: http.StatusConflict,
				}
			}
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		statusCode = http.StatusCreated
	} else { // update
		if err := writePack(item, input.UserID, aws.Bool(true)); err != nil {
			if err == errNotExists || err == errWrongType {
				// errWrongType means we tried to modify a pack that is actually a different detection type.
				// In this case return 404 - the pack you tried to modify does not exist.
				return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
			}
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		statusCode = http.StatusOK
	}

	return gatewayapi.MarshalResponse(item.Pack(), statusCode)
}

func updatePackDetections(userID string, pack *packTableItem, release models.Release) error {
	// check the pack & detection cache
	if time.Since(cacheLastUpdated) > cacheTimeout || cacheVersion.ID != release.ID {
		// cache has timed out or cache has wrong detection version
		// Retrieve new version of detections
		err := downloadValidatePackData(release)
		if err != nil {
			return err
		}
	}
	// First lookup the existing detections in this pack
	detections, err := detectionLookup(pack.DetectionPattern)
	if err != nil {
		return err
	}
	// Then get a list of the updated detection in the pack
	newDetections, err := detectionCacheLookup(pack.DetectionPattern)
	if err != nil {
		return err
	}
	// simply loop through the new detections and update appropriate fields or
	//  create new detection
	for id, newDetection := range newDetections {
		if detection, ok := detections[id]; ok {
			// update existing detection
			detection.Body = newDetection.Body
			detection.DedupPeriodMinutes = newDetection.DedupPeriodMinutes
			detection.Description = newDetection.Description
			detection.Enabled = pack.Enabled
			detection.ResourceTypes = newDetection.ResourceTypes // aka LogTypes
			detection.Reference = newDetection.Reference
			detection.Reports = newDetection.Reports
			detection.Runbook = newDetection.Runbook
			detection.Tags = newDetection.Tags
			detection.Tests = newDetection.Tests
			detection.Threshold = newDetection.Threshold
			_, err = writeItem(detection, userID, aws.Bool(true))
			if err != nil {
				// TODO: should we try to rollback the other updated detections?
				return err
			}
		} else {
			// create new detection
			_, err = writeItem(newDetection, userID, aws.Bool(false))
			if err != nil {
				// TODO: should we try to rollback the other updated detections?
				return err
			}
		}
	}
	return nil
}

func updatePackReleases(newRelease models.Release, oldPacks []packTableItem) error {
	if time.Since(cacheLastUpdated) > cacheTimeout || cacheVersion.ID != newRelease.ID {
		// cache has timed out or cache has wrong detection version
		// Retrieve new version of detections
		err := downloadValidatePackData(newRelease)
		if err != nil {
			return err
		}
	}
	oldPacksMap := make(map[string]packTableItem)
	// convert oldPacks to a map for ease of comparison
	for _, oldPack := range oldPacks {
		oldPacksMap[oldPack.ID] = oldPack
	}
	// Loop through new packs. Old/deprecated packs will simply not get updated
	for id, newPack := range packCache {
		if oldPack, ok := oldPacksMap[id]; ok {
			// Update existing pack metadata fields: AvailableReleases and UpdateAvailable
			if !containsRelease(oldPack.AvailableReleases, newRelease) {
				// only add the new release to the availableReleases if it is not already there
				oldPack.AvailableReleases = append(oldPack.AvailableReleases, newRelease)
			}
			oldPack.UpdateAvailable = true
			err := writePack(&oldPack, oldPack.CreatedBy, aws.Bool(false)) // TODO: any issue with preserving the old user id?
			if err != nil {
				// TODO: should this be fatal? Or continue and ignore that some failed?
				return err
			}
		} else {
			// Add a new pack, and auto-disable it. AvailableReleases will only
			// contain the version where it was added
			newPack.Enabled = false
			newPack.AvailableReleases = []models.Release{newRelease}
			newPack.UpdateAvailable = true
			newPack.EnabledRelease = models.Release{
				ID:      0,
				Version: defaultVersion,
			}
			err := writePack(&oldPack, systemUserID, aws.Bool(false))
			if err != nil {
				// TODO: should this be fatal? Or continue and ignore that some failed?
				return err
			}
		}
	}
	return nil
}

func updatePackMetadata(userID string, item *packTableItem, release models.Release) error {
	// check the pack & detection cache
	if time.Since(cacheLastUpdated) > cacheTimeout || cacheVersion.ID != release.ID {
		// cache has timed out or cache has wrong detection version
		// Retrieve new version of detections
		err := downloadValidatePackData(release)
		if err != nil {
			return err
		}
	}
	if newPack, ok := packCache[item.ID]; ok {
		// update the metadata fields. Note: use incoming enabled status
		// TODO: what to do about the 'updateAvailable' flag?
		pack := &packTableItem{
			Enabled:           item.Enabled,
			UpdateAvailable:   false,
			Description:       newPack.Description,
			DetectionPattern:  newPack.DetectionPattern,
			DisplayName:       newPack.DisplayName,
			EnabledRelease:    release,
			ID:                item.ID,
			AvailableReleases: item.AvailableReleases,
		}
		// write the updated values
		err := writePack(pack, userID, aws.Bool(false)) // TODO: what to do about getting the UserID in here?
		if err != nil {
			// should this be fatal? Or continue and ignore that some failed?
			return err
		}
	} else {
		// This is a deprecated / delete pack - it got to this point in error
		zap.L().Error("Trying to update a deprecated pack",
			zap.String("pack", item.ID),
			zap.String("version", release.Version))
	}
	return nil
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
	scanInput, err := buildScanInput(models.TypePack, []string{}, filters...)
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

func detectionCacheLookup(input models.DetectionPattern) (map[string]*tableItem, error) {
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

	return items, nil
}

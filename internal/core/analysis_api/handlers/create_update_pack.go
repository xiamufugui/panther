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
	if input.Enabled != item.Enabled || input.EnabledRelease != item.EnabledRelease {
		detections, err := detectionLookup(item.DetectionPatterns)
		if err != nil {
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		// If we are updating the detections themselves, do both updates at the same time
		if input.EnabledRelease != item.EnabledRelease {
			// TODO: this will be implemented in another PR / Task, basic outline:
			// First, retrieve the new versions of the detections (and cache those results?)
			// Second, retrieve the detections from ddb
			// Loop through and update the detections (and 'enabled' status from the input.Enabled)
		} else {
			// Otherwise, we are simply updating the enablement status of the detections
			// in this pack
			for i, detection := range detections {
				if detection.Enabled != input.Enabled {
					detection.Enabled = input.Enabled
					_, err = writeItem(&detections[i], input.UserID, aws.Bool(true))
					if err != nil {
						return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
					}
				}
			}
		}
		// Then, Update the enablement status and enabledRelease of the pack itself
		updateInput := models.UpdatePackInput{
			Description:       item.Description,
			DetectionPatterns: item.DetectionPatterns,
			DisplayName:       item.DisplayName,
			Enabled:           input.Enabled,
			EnabledRelease:    input.EnabledRelease,
			Source:            item.Source,
			UpdateAvailable:   item.UpdateAvailable,
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
		DetectionPatterns: input.DetectionPatterns,
		DisplayName:       input.DisplayName,
		Enabled:           input.Enabled,
		EnabledRelease:    input.EnabledRelease,
		Source:            input.Source,
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

func detectionLookup(input []models.DetectionPattern) ([]tableItem, error) {
	var items []tableItem

	for _, pattern := range input {
		var filters []expression.ConditionBuilder

		// Currently only support specifying IDs
		if len(pattern.IDs) > 0 {
			idFilter := expression.AttributeNotExists(expression.Name("lowerId"))
			for _, id := range pattern.IDs {
				idFilter = idFilter.Or(expression.Contains(expression.Name("lowerId"), id))
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
			items = append(items, item)
			return nil
		})
		if err != nil {
			zap.L().Error("failed to scan detections", zap.Error(err))
			return nil, err
		}
	}
	return items, nil
}

//func retrieveDetectionUpdates(release string) (map[string]*tableItem, error) {
// This is to be implemented in another task / PR but here is the basic outline:
// retrieve the release version of detections from panther-analysis and return them as a slice
// of table items
//	return nil, nil
//}

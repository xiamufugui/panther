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

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) CreatePack(input *models.UpdatePackInput) *events.APIGatewayProxyResponse {
	return writePack(input, true)
}

func (API) PatchPack(input *models.PatchPackInput) *events.APIGatewayProxyResponse {
	// This is a partial update, so lookup existing item values
	var item *tableItem
	item, err := dynamoGet(input.ID, false)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Internal error finding %s (%s)", input.ID, models.TypePack),
			StatusCode: http.StatusInternalServerError,
		}
	}
	if item == nil || item.Type != models.TypePack {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Cannot find %s (%s)", input.ID, models.TypePack),
			StatusCode: http.StatusNotFound,
		}
	}
	// Update the enabled status if it has changed
	if item.Enabled != input.Enabled {
		updateInput := models.UpdatePackInput{
			Description:     item.Description,
			DetectionQuery:  item.DetectionQuery,
			DisplayName:     item.DisplayName,
			Enabled:         input.Enabled,
			Release:         item.Release,
			Source:          item.Source,
			UpdateAvailable: item.UpdateAvailable,
		}
		return writePack(&updateInput, false)
	}
	// Nothing to update, report success
	return gatewayapi.MarshalResponse(item.Pack(), http.StatusOK)
}

func (API) UpdatePack(input *models.UpdatePackInput) *events.APIGatewayProxyResponse {
	return writePack(input, false)
}

func (API) UpdatePackDetections(input *models.UpdatePackDetectionsInput) *events.APIGatewayProxyResponse {
	// TODO: update pack detections

}

func writePack(input *models.UpdatePackInput, create bool) *events.APIGatewayProxyResponse {
	item := &tableItem{
		Description:     input.Description,
		DetectionQuery:  input.DetectionQuery,
		DisplayName:     input.DisplayName,
		Enabled:         input.Enabled,
		Release:         input.Release,
		Source:          input.Source,
		UpdateAvailable: input.UpdateAvailable,
	}

	var statusCode int

	if create {
		if _, err := writeItem(item, input.UserID, aws.Bool(false)); err != nil {
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
		if _, err := writeItem(item, input.UserID, aws.Bool(true)); err != nil {
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

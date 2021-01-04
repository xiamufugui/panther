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
	"net/url"

	"github.com/aws/aws-lambda-go/events"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

func (API) RevertPack(input *models.RevertPackInput) *events.APIGatewayProxyResponse {
	return handleRevert(input.ID, input.VersionID, models.TypePack)
}

// Handle revert request for Detections and Packs
func handleRevert(itemID, versionID string, codeType models.DetectionType) *events.APIGatewayProxyResponse {
	var err error
	itemID, err = url.QueryUnescape(itemID)
	if err != nil {
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusBadRequest}
	}

	var item *tableItem
	if versionID == "" {
		// revert to previous is no versionID is provided
	} else {
		item, err = s3Get(itemID, versionID)
	}

	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Internal error finding %s (%s)", itemID, codeType),
			StatusCode: http.StatusInternalServerError,
		}
	}
	if item == nil || item.Type != codeType {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Cannot find %s (%s)", itemID, codeType),
			StatusCode: http.StatusNotFound,
		}
	}

	switch codeType {
	case models.TypePack:
		updateInput := models.UpdatePackInput{
			Description:     item.Description,
			DetectionQuery:  item.DetectionQuery,
			DisplayName:     item.DisplayName,
			Enabled:         item.Enabled,
			Release:         item.Release,
			Source:          item.Source,
			UpdateAvailable: item.UpdateAvailable,
		}
		writePack(&updateInput, false)
		// TODO: Loop through detections in pack and revert them too - call list_packs with filter built on detection query
		// revert all of those detections ; basically get latest version from dynamo and run s3Delete, which will revert to the previous?
		// https://docs.aws.amazon.com/AmazonS3/latest/dev/RestoringPreviousVersions.html
		return nil
	default:
		panic("unexpected codeType " + codeType)
	}
}

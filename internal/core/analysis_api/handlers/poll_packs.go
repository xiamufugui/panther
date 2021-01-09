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
	"github.com/aws/aws-lambda-go/events"
	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

func (API) PollPacks(input *models.PollPacksInput) *events.APIGatewayProxyResponse {
	// TODO: this work will be done in another PR / task, but here is an outline
	// First, retrieve & validate all the packs in the panther-analysis repo

	// Second, lookup existing item values to determine if updates are available

	// Finally, loop through each pack and CHECK if update is available / create a new pack:
	// update fields: availableReleases and updateAvailable status of the detections in the pack
	// AND create any _new_ packs (default to disabled status)

	// If there is nothing to update, report success
	return nil
}

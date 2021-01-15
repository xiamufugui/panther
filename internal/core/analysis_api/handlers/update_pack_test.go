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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

func TestDetectionCacheLookup(t *testing.T) {
	detectionOne := &tableItem{
		ID: "id.1",
	}
	detectionTwo := &tableItem{
		ID: "id.2",
	}
	detectionThree := &tableItem{
		ID: "id.3",
	}
	// only ids that exist
	detectionCache = map[string]*tableItem{
		"id.1": detectionOne,
		"id.2": detectionTwo,
		"id.3": detectionThree,
	}
	detectionPattern := models.DetectionPattern{
		IDs: []string{"id.1", "id.3"},
	}
	expectedOutput := map[string]*tableItem{
		"id.1": detectionOne,
		"id.3": detectionThree,
	}
	items, err := detectionCacheLookup(detectionPattern)
	assert.Equal(t, items, expectedOutput)
	assert.NoError(t, err)
	// only ids that do not exist
	detectionPattern = models.DetectionPattern{
		IDs: []string{"id.4", "id.6"},
	}
	expectedOutput = map[string]*tableItem{}
	items, err = detectionCacheLookup(detectionPattern)
	assert.Equal(t, items, expectedOutput)
	assert.NoError(t, err)
	// mix of ids that exist and do not exist
	detectionPattern = models.DetectionPattern{
		IDs: []string{"id.1", "id.6"},
	}
	expectedOutput = map[string]*tableItem{
		"id.1": detectionOne,
	}
	items, err = detectionCacheLookup(detectionPattern)
	assert.Equal(t, items, expectedOutput)
	assert.NoError(t, err)
}

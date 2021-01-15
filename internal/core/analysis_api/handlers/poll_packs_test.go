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

func TestIsNewReleaseAvailable(t *testing.T) {
	release := models.Release{
		ID: 2222, Version: "v1.2.0",
	}
	enabledRelease := models.Release{
		Version: "v0.1.0",
	}
	currentPacks := []packTableItem{
		{
			EnabledRelease: enabledRelease,
		},
	}
	// Test new release is available
	result := isNewReleaseAvailable(release, currentPacks)
	assert.True(t, result)
	// Test at current release
	enabledRelease = models.Release{
		Version: "v1.2.0",
	}
	currentPacks = []packTableItem{
		{
			EnabledRelease: enabledRelease,
		},
	}
	result = isNewReleaseAvailable(release, currentPacks)
	assert.False(t, result)
	// Test malformed version string
	enabledRelease = models.Release{
		Version: "-a.1.0",
	}
	currentPacks = []packTableItem{
		{
			EnabledRelease: enabledRelease,
		},
	}
	result = isNewReleaseAvailable(release, currentPacks)
	assert.False(t, result)
}

func TestContainsRelease(t *testing.T) {
	releases := []models.Release{
		{ID: 1111, Version: "v1.1.0"},
		{ID: 2222, Version: "v1.2.0"},
	}
	contains := models.Release{
		ID:      1111,
		Version: "v1.1.0",
	}
	result := containsRelease(releases, contains)
	assert.True(t, result)
	doesNotContain := models.Release{
		ID:      3333,
		Version: "v1.3.0",
	}
	result = containsRelease(releases, doesNotContain)
	assert.False(t, result)
}

func TestGetLatestRelease(t *testing.T) {
	expectedRelease := models.Release{
		ID:      3333,
		Version: "v1.3.0",
	}
	firstRelease := models.Release{
		ID:      1111,
		Version: "v1.1.0",
	}
	secondRelease := models.Release{
		ID:      2222,
		Version: "v1.2.0",
	}
	releases := []models.Release{
		firstRelease,
		secondRelease,
		expectedRelease,
	}
	result := getLatestRelease(releases)
	assert.Equal(t, result, expectedRelease)
	// validate in different order
	releases = []models.Release{
		secondRelease,
		expectedRelease,
		firstRelease,
	}
	result = getLatestRelease(releases)
	assert.Equal(t, result, expectedRelease)

}

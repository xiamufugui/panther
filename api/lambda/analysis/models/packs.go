package models

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
	"time"
)

type DeletePacksInput = DeleteEntriesInput

type GetPackInput struct {
	ID string `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	//VersionID string `json:"versionId" validate:"omitempty,len=32"` // TODO: will this be in S3?
}

type ListPacksInput struct {
	// ----- Filtering -----
	// Only include packs which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include packs which have this enabledRelease
	EnabledVersion Version `json:"enabledVersion"`

	// Only include packs whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains" validate:"max=1000"`

	// Only include packs that have updates available
	UpdateAvailable *bool `json:"updateAvailable"`

	// ----- Projection -----
	// Fields to return in the response (default: all)
	Fields []string `json:"fields" validate:"max=20,dive,required,max=100"`

	// ----- Sorting ----- TODO: not supported in first version

	// ----- Paging -----
	PageSize int `json:"pageSize" validate:"min=0,max=1000"`
	Page     int `json:"page" validate:"min=0"`
}

type ListPacksOutput struct {
	Paging Paging `json:"paging"`
	Packs  []Pack `json:"packs"`
}

type PatchPackInput struct {
	// This is a partial update
	Enabled        bool    `json:"enabled"`
	EnabledVersion Version `json:"enabledVersion"`
	ID             string  `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	UserID         string  `json:"userId" validate:"required"`
}

// PollPacksInput will also update the pack metadata: "availableReleases" and "updateAvailable"
type PollPacksInput struct {
	// PollPacksInput allows for specifying a specific relase to poll or not
	ReleaseVersion Version `json:"releaseVersion"`
}

type Pack struct {
	Enabled           bool             `json:"enabled"`
	UpdateAvailable   bool             `json:"updateAvailable"`
	CreatedBy         string           `json:"createdBy"`
	Description       string           `json:"description"`
	DisplayName       string           `json:"displayName"`
	EnabledVersion    Version          `json:"enabledVersion"`
	ID                string           `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	LastModifiedBy    string           `json:"lastModifiedBy"`
	Type              string           `json:"type"`
	UserID            string           `json:"userId"`
	VersionID         string           `json:"versionId"` // TODO: VersionID ? (will this be in S3?)
	CreatedAt         time.Time        `json:"createdAt"`
	LastModified      time.Time        `json:"lastModified"`
	AvailableVersions []Version        `json:"availableVersions"`
	DetectionPattern  DetectionPattern `json:"detectionPatterns"`
}

type DetectionPattern struct {
	IDs []string `json:"IDs"`
}

type Version struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

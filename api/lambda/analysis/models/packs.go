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

type CreatePackInput = UpdatePackInput

type DeletePacksInput = DeletePoliciesInput

type GetPackInput struct {
	ID        string `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	VersionID string `json:"versionId" validate:"omitempty,len=32"` // TODO: will this be in S3?
}

type ListPacksInput struct {
	// ----- Filtering -----
	// Only include packs who have one of these available release
	AvailableReleases []string `json:"availableReleases"`

	// Only include packs whose creator matches this user ID (which need not be a uuid)
	CreatedBy string `json:"createdBy"`

	// Only include packs which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include packs which have this enabledRelease
	EnabledRelease string `json:"enabledRelease"`

	// Only include packs which were last modified by this user ID
	LastModifiedBy string `json:"lastModifiedBy"`

	// Only include packs that are managed
	Managed *bool `json:"managed"`

	// Only include packs whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains" validate:"max=1000"`

	// Only inlude packs from a particular source
	Source string `json:"source"`

	// Only include packs that have updates available
	UpdateAvailable *bool `json:"updateAvailable"`

	// ----- Projection -----
	// Fields to return in the response (default: all)
	Fields []string `json:"fields" validate:"max=20,dive,required,max=100"`

	// ----- Sorting ----- TODO see notes in "list_packs.go"
	//SortBy  string `json:"sortBy" validate:"omitempty,oneof=displayName enabled id lastModified logTypes severity"`
	//SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

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
	Enabled        bool   `json:"enabled"`
	EnabledRelease string `json:"enabledRelease"`
	ID             string `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	UserID         string `json:"userId" validate:"required"`
}

// PollPacksInput will also update the pack metadata: "availableReleases" and "updateAvailable"
type PollPacksInput struct {
	// PollPacksInput will be similar to ListPacksInput, in that there are several
	// ways to specify which packs you would like to poll for updates
	// Poll packs whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains" validate:"max=1000"`

	// Poll packs that are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Poll panther-managed packs
	Managed *bool `json:"managed"`

	// Poll packs from a particular source
	Source string `json:"source"`
}

// This struct is used to build a new Pack or used by Patch operation to update certain fields
type UpdatePackInput struct {
	Enabled           bool     `json:"enabled"`
	UpdateAvailable   bool     `json:"updateAvailable"`
	Description       string   `json:"description"`
	DetectionQuery    string   `json:"detectionQuery"`
	DisplayName       string   `json:"displayName"`
	EnabledRelease    string   `json:"enabledRelease"`
	ID                string   `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	Source            string   `json:"source"`
	UserID            string   `json:"userId" validate:"required"`
	AvailableReleases []string `json:"availableReleases"`
	DetectionIDs      []string `json:"detectionIds"`
}

type Pack struct {
	Enabled           bool      `json:"enabled"`
	Managed           bool      `json:"managed"`
	UpdateAvailable   bool      `json:"updateAvailable"`
	CreatedAt         time.Time `json:"createdAt"`
	CreatedBy         string    `json:"createdBy"`
	Description       string    `json:"description"`
	DetectionQuery    string    `json:"detectionQuery"`
	DisplayName       string    `json:"displayName"`
	EnabledRelease    string    `json:"enabledRelease"`
	ID                string    `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	LastModified      time.Time `json:"lastModified"`
	LastModifiedBy    string    `json:"lastModifiedBy"`
	Source            string    `json:"source"`
	VersionID         string    `json:"versionId"` // TODO: VersionID ? (will this be in S3?)
	AvailableReleases []string  `json:"availableReleases"`
	DetectionIDs      []string  `json:"detectionIds"`
}

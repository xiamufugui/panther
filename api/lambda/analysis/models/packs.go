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
	ID        string `json:"id" validate:"required,max=1000"`
	VersionID string `json:"versionId" validate:"omitempty,len=32"`
}

type ListPacksInput struct {
	// ----- Filtering -----
	// Only include rules whose creator matches this user ID (which need not be a uuid)
	CreatedBy string `json:"createdBy"`

	// Only include packs whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains" validate:"max=1000"`

	// Only include packs which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include packs which apply to one of these detection IDs
	DetectionIDs []string `json:"detectionIDs" validate:"max=500,dive,required,max=500"`

	// Only include rules which were last modified by this user ID
	LastModifiedBy string `json:"lastModifiedBy"`

	// Only include packs that are managed
	Managed *bool `json:"managed"`

	// Only include packs that have updates available
	UpdateAvailable *bool `json:"updateAvailable"`

	// ----- Projection -----
	// Policy fields to return in the response (default: all)
	Fields []string `json:"fields" validate:"max=20,dive,required,max=100"`

	// ----- Sorting -----
	SortBy  string `json:"sortBy" validate:"omitempty,oneof=displayName enabled id lastModified logTypes severity"`
	SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

	// ----- Paging -----
	PageSize int `json:"pageSize" validate:"min=0,max=1000"`
	Page     int `json:"page" validate:"min=0"`
}

type PollPacksInput struct {
	Managed *bool `json:"managed"`
}

type ListPacksOutput struct {
	Paging Paging `json:"paging"`
	Packs  []Pack `json:"packs"`
}

type PatchPackInput struct {
	// in the UI will will only allow users to update enabled/disabled status and "revert to previous"
	// BUT should we expose other ways to update packs here for in the future?
	// e.g. if a user want to define their own pack using the UI, this would be the
	// the way to update it?
	Enabled   bool   `json:"enabled"`
	UserID    string `json:"userId" validate:"required"`
	VersionID string `json:"versionId"`
}

type UpdatePackInput struct {
	// in the UI will will only allow users to update enabled/disabled status and "revert to previous"
	// BUT should we expose other ways to update packs here for in the future?
	// e.g. if a user want to define their own pack using the UI, this would be the
	// the way to update it?
	Description     string `json:"description"`
	DetectionQuery  string `json:"detectionQuery"`
	DisplayName     string `json:"displayName"`
	Enabled         bool   `json:"enabled"`
	Source          string `json:"source"`
	UserID          string `json:"userId" validate:"required"`
	UpdateAvailable bool   `json:"updateAvailable"`
}

type Pack struct {
	CreatedAt       time.Time `json:"createdAt"`
	CreatedBy       string    `json:"createdBy"`
	Description     string    `json:"description"`
	DetectionQuery  string    `json:"detectionQuery"`
	DisplayName     string    `json:"displayName"`
	Enabled         bool      `json:"enabled"`
	ID              string    `json:"id"`
	LastModified    time.Time `json:"lastModified"`
	LastModifiedBy  string    `json:"lastModifiedBy"`
	Managed         bool      `json:"managed"`
	Source          string    `json:"source"`
	UpdateAvailable bool      `json:"updateAvailable"`
	VersionID       string    `json:"versionId"`
}

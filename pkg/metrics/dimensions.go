package metrics

import (
	"strings"
)

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

const (

	// SubsystemDimension dimension
	SubsystemDimension     = "SubsystemDimension"
	SubsystemDestinations  = "Destinations"
	SubsystemLogProcessing = "LogProcessing"
	SubsystemDetections    = "Detections"
	SubsystemDatalake      = "Datalake"

	// StatusDimension dimension
	StatusDimension = "StatusDimension"
	// StatusDimension indicating that a subsystem operation is well
	StatusOk = "Ok"
	// StatusDimension indicating that a subsystem is experiencing authZ/N errors
	StatusAuthErr = "AuthErr"
	// StatusDimension indicating some general error with the subsystem
	StatusErr = "Err"

	// IDDimension dimensions
	IDDimension = "ID"
)

// Returns the correct Status dimension from the provided error
func StatusFromErr(err error) string {
	if err == nil {
		return StatusOk
	}
	if strings.Contains(err.Error(), "AccessDenied") {
		return StatusAuthErr
	}
	return StatusErr
}

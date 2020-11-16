package registry

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
)

// Generates an init() function that populates the registry with all log types exported by
// packages inside "internal/log_analysis/log_processor/parsers/..."
//go:generate go run ./generate_init.go ../parsers/...

// These will be populated by the generated init() code
var (
	nativeLogTypes    logtypes.Group
	availableLogTypes = &logtypes.Registry{}
)

// NativeLogTypesResolver returns a resolver for native log types.
// Use this instead of registry.Default()
func NativeLogTypesResolver() logtypes.Resolver {
	return logtypes.LocalResolver(nativeLogTypes)
}
func NativeLogTypes() logtypes.Group {
	return nativeLogTypes
}

// LogTypes exposes all available log types as a read-only group.
func LogTypes() logtypes.Group {
	return availableLogTypes
}

// AvailableLogTypes returns all available log types in the default registry
func AvailableLogTypes() (logTypes []string) {
	for _, e := range LogTypes().Entries() {
		logTypes = append(logTypes, e.String())
	}
	return
}

package clean

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
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

func Clean() error {

	// Set of paths to remove = init with static remove paths
	rmPaths := []string{
		util.SetupDir,
		util.NpmDir,
		"out",
		"internal/core/analysis_api/main/bulk_upload.zip",
	}

	// Add Dynamic Paths to remove paths set:
	rmPaths = append(rmPaths, util.GatherPyCacheFiles(util.PyTargets)...)

	// Remove files (checks paths are sub-paths of PantherRoot)
	// Dry run (skip actually removing things) with 2nd argument 'enableRm'
	return cleanPantherPathSet(rmPaths, true)
}

// Removes files at paths in set (if they are descendents of PantherRoot).
// Dry run by setting enableRM to false
func cleanPantherPathSet(pathSet []string, enableRM bool) error {
	log := logger.Build("[clean]")
	rmCount := 0
	errCount := 0
	pantherRoot := util.PantherRoot()
	log.Info("Clean: ", len(pathSet), ", remove enabled: ", enableRM)

	for _, target := range pathSet {
		// Normalize target to abs path if it is not an abs path
		rmSystemPath := util.PantherFullPath(target)

		// Skip paths that are not sub-paths of PantherRoot
		if isf, _ := util.IsPathDescendantOf(rmSystemPath, pantherRoot); !isf {
			log.Error("attempted rm on non-panther path: ", rmSystemPath)
			errCount += 1
			continue
		}

		// Get the pantherRoot relative path
		rel, err := util.PantherRelPath(rmSystemPath)
		if err != nil {
			log.Error("util.PantherRelPath error: ", err)
			errCount += 1
			continue
		}

		// Skip paths that don't point to an existing file
		if !util.FilePathExists(rmSystemPath) {
			log.Warn("no file: ", rel)
			continue
		}

		// Actually Attempt to remove item located at rmSystemPath
		log.Info("rm -r ", rel)
		if !enableRM {
			continue
		}

		if err := util.RmPath(rmSystemPath); err != nil {
			log.Error("rm path: ", rel, ", error: ", err)
			errCount += 1
			continue
		}

		rmCount += 1
	}

	log.Info("removed: ", rmCount, "/", len(pathSet), ", errors: ", errCount)
	return nil
}

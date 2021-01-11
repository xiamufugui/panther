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

// Remove dev libraries and build/test artifacts
func Clean() error {
	log := logger.Build("[clean]")

	// Set of static paths to remove (paths relative to panther repo root)
	rmPaths := []string{
		util.SetupDir,
		util.NpmDir,
		"out",
		"internal/core/analysis_api/main/bulk_upload.zip",
	}

	// Add __pycache__ files
	log.Info("Adding __pycache__ files to clean set")
	for _, target := range util.PyTargets {
		rmPaths = append(rmPaths, gatherPyCacheFiles(target)...)
	}

	log.Info("Clean: ", len(rmPaths))

	// Remove files found at paths in rmPaths.
	// Only remove files that are descendants of the repository root
	rmCount, errCount := cleanPantherPathSet(rmPaths)

	log.Info("Clean Panther Paths Completed")
	log.Info("removed: ", rmCount, "/", len(rmPaths), ", errors: ", errCount)
	return nil
}

// Gather all files with __pycache__ suffix relative to target path
func gatherPyCacheFiles(target string) []string {
	// adjust target path if target is not an absolute path
	searchTarget := util.PantherFullPath(target)
	return util.DirFilesWithNameSuffix(searchTarget, "__pycache__")
}

// Removes files at paths in set (if they are descendents of PantherRoot)
func cleanPantherPathSet(pathSet []string) (rmCount int, errCount int) {
	log := logger.Build("[clean]")
	pantherRoot := util.PantherRoot()
	// for _, target := range pathSet {
	for _, target := range pathSet {
		// Normalize target to abs path if it is not an abs path
		rmSystemPath := util.PantherFullPath(target)
		// log.Info("rm path: ", rmSystemPath)
		if isf, _ := util.IsPathDescendantOf(rmSystemPath, pantherRoot); isf {
			if util.FilePathExists(rmSystemPath) {
				if err := util.RmPath(rmSystemPath); err == nil {
					rel, _ := util.PantherRelPath(rmSystemPath)
					log.Info("rm -r ", rel)
					rmCount += 1
				} else {
					log.Error("rm path: ", rmSystemPath, ", error: ", err)
					errCount += 1
				}
			} else {
				log.Warn("No file: ", rmSystemPath)
			}
		} else {
			log.Error("attempted rm on non-panther path: ", rmSystemPath)
			errCount += 1
		}
	}
	return
}

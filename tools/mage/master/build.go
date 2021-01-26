package master

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
	"bytes"
	"path/filepath"

	"github.com/aws/aws-sdk-go/service/ecr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/tools/mage/build"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/util"
)

// Build lambda functions, python layer, and docker image in parallel.
//
// Returns docker image ID.
func buildAssets(log *zap.SugaredLogger, pipLayer []string) (string, error) {
	results := make(chan util.TaskResult)
	count := 0
	var imageID string

	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: "build:lambda", Err: build.Lambda()}
	}(results)

	count++
	go func(c chan util.TaskResult) {
		c <- util.TaskResult{Summary: "pip install layer", Err: build.Layer(log, pipLayer)}
	}(results)

	count++
	go func(c chan util.TaskResult) {
		var err error
		imageID, err = deploy.DockerBuild(filepath.Join("deployments", "Dockerfile"))
		c <- util.TaskResult{Summary: "docker build", Err: err}
	}(results)

	if err := util.WaitForTasks(log, results, 1, count, count); err != nil {
		return "", err
	}

	return imageID, nil
}

// Package assets needed for the master template.
//
// Returns the path to the final generated template.
func pkgAssets(log *zap.SugaredLogger, ecrClient *ecr.ECR, region, bucket, imgRegistry, dockerImageID string) (string, error) {
	pkg, err := util.SamPackage(region, rootTemplate, bucket)
	if err != nil {
		return "", err
	}

	// Embed the version directly into the final template - we don't want this to be a configurable parameter.
	//
	// There is roughly a 1.4% chance that the commit tag looks like scientific notation, e.g. "715623e8"
	// Even if the value is surrounded by quotes in the original template, `sam package` will remove them!
	// Then CloudFormation will standardize the scientific notation, e.g. "7.15623E13"
	//
	// So, until we implement our own packaging, we have to do the version embedding *after* sam package.
	template := util.MustReadFile(pkg)
	template = bytes.Replace(template, []byte("${{PANTHER_COMMIT}}"), []byte(`'`+util.CommitSha()+`'`), 1)
	template = bytes.Replace(template, []byte("${{PANTHER_VERSION}}"), []byte(`'`+util.Semver()+`'`), 1)
	util.MustWriteFile(pkg, template)

	dockerImage, err := deploy.DockerPush(ecrClient, imgRegistry, dockerImageID, util.Semver())
	if err != nil {
		return "", err
	}

	log.Infof("successfully published docker image %s", dockerImage)
	return pkg, nil
}

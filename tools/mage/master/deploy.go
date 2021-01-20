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
	"fmt"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudformation"

	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/logger"
)

const devStackName = "panther-dev"

var (
	devTemplate  = filepath.Join("deployments", "dev.yml")
	rootTemplate = filepath.Join("deployments", "root.yml")
)

// Deploy the root template nesting all other stacks.
func Deploy() error {
	log := logger.Build("[master:deploy]")
	if err := deployPreCheck(); err != nil {
		return err
	}

	outputs, err := deploy.Stack(devTemplate, "", devStackName, nil)
	if err != nil {
		return err
	}

	// TODO - mage clean should remove the root_config.yml file
	_, err = buildRootConfig(log, outputs["ImageRegistryUri"])
	if err != nil {
		return err
	}

	return nil

	/*
		1. Deploy panther-dev
		2. go build / docker build in parallel
		3. package assets
		4. Deploy root stack
	*/

	//log.Infof("deploying %s %s (%s) to %s (%s) as stack '%s'", rootTemplate,
	//	util.Semver(), util.CommitSha(), clients.AccountID(), clients.Region(), stack)
	//email := prompt.Read("First user email: ", prompt.EmailValidator)
	//
	//dockerImageID, err := buildAssets(log)
	//if err != nil {
	//	return err
	//}
	//
	//pkg, err := pkgAssets(log, clients.ECR(), clients.Region(), bucket, registryURI, dockerImageID)
	//if err != nil {
	//	return err
	//}
	//
	//params := []string{"FirstUserEmail=" + email, "ImageRegistry=" + registryURI}
	//if p := os.Getenv("PARAMS"); p != "" {
	//	// Assume no spaces in the parameter values
	//	params = append(params, strings.Split(p, " ")...)
	//}
	//
	//return util.SamDeploy(stack, pkg, params...)
}

// Stop early if there is a known issue with the dev environment.
func deployPreCheck() error {
	if err := deploy.PreCheck(); err != nil {
		return err
	}

	_, err := clients.Cfn().DescribeStacks(
		&cloudformation.DescribeStacksInput{StackName: aws.String(cfnstacks.Bootstrap)})
	if err == nil {
		// Multiple Panther deployments won't work in the same region in the same account.
		// Named resources (e.g. IAM roles) will conflict
		// TODO - the stack migration will happen here
		return fmt.Errorf("%s stack already exists, can't deploy root template", cfnstacks.Bootstrap)
	}

	return nil
}

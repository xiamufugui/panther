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
	"archive/zip"
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/hashicorp/go-version"
	"github.com/panther-labs/panther/api/lambda/analysis"
	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

func (API) PollPacks(input *models.PollPacksInput) *events.APIGatewayProxyResponse {
	// First, check for a new release in the github repo
	releases, err := listAvailableGithubReleases()
	if err != nil {
		// error looking up the github releases
		zap.L().Error("failed to list github releases", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	if releases == nil || len(releases) == 0 {
		// there aren't any releases, just return
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
	}
	// Second, lookup existing item values to determine if updates are available
	currentPacks, err := getPackItems(&dynamodb.ScanInput{
		TableName: &env.PackTable,
	})
	if err != nil {
		// error looking up the existing pack data
		zap.L().Error("failed to scan panther-analysis-pack table", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	// Finally, check if update is available
	latestRelease := getLatestRelease(releases)
	if isNewReleaseAvailable(latestRelease, currentPacks) {
		// If an update is available, retrieve & validate pack data and:
		// Update fields: availableReleases and updateAvailable status of the detections in the pack
		// Create any new packs: default to disabled status
		// TODO: what this doesn't handle is when there are multiple new releases that need to be registered
		err := updatePackReleases(latestRelease, currentPacks)
		if err != nil {
			// error updating pack data
			zap.L().Error("failed to update pack releases", zap.Error(err))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
	}
	// Nothing else to do - Report success
	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

func isNewReleaseAvailable(latestRelease models.Release, currentPacks []packTableItem) bool {
	latestReleaseVersion, err := version.NewVersion(latestRelease.Version)
	if err != nil {
		// Failed to parse the version string
		zap.L().Error("Failed to parse the version string for a release",
			zap.String("versionString", latestRelease.Version))
		return false
	}
	// this is a lazy way to check for a new version -
	// if any current pack verison is less the the latest version
	// in the repo, report a new version is available to download
	for _, pack := range currentPacks {
		version, err := version.NewVersion(pack.EnabledRelease.Version)
		if err != nil {
			continue
		}
		if version.LessThan(latestReleaseVersion) && !containsRelease(pack.AvailableReleases, latestRelease) {
			return true
		}
	}
	return false
}

func containsRelease(releases []models.Release, newRelease models.Release) bool {
	for _, release := range releases {
		if release.ID == newRelease.ID {
			return true
		}
	}
	return false
}

func getLatestRelease(releases []models.Release) models.Release {
	latestRelease := releases[0]
	latestReleaseVersion, err := version.NewVersion(latestRelease.Version)
	if err != nil {
		zap.L().Error("error parsing version string", zap.String("version", latestRelease.Version))
		return latestRelease
	}
	for _, release := range releases {
		version, err := version.NewVersion(release.Version)
		if err != nil {
			continue
		}
		if version.GreaterThan(latestReleaseVersion) {
			latestRelease = release
			latestReleaseVersion = version
		}
	}
	return latestRelease
}

func validateSignature(rawData []byte, signature []byte) error {
	// use hash of body in validation
	intermediateHash := sha512.Sum512(rawData)
	var computedHash []byte = intermediateHash[:]
	signatureVerifyInput := &kms.VerifyInput{
		KeyId:            aws.String(signingKeyID),
		Message:          computedHash,
		MessageType:      aws.String(kms.MessageTypeDigest),
		Signature:        signature,
		SigningAlgorithm: aws.String(signingAlgorithm),
	}
	result, err := kmsClient.Verify(signatureVerifyInput)
	if err != nil {
		zap.L().Error("error validating signature", zap.Error(err))
		return err
	}
	if *result.SignatureValid {
		return nil
	}
	return errors.New("Error validating signature")
}

func extractPackZipFileBytes(content []byte) (map[string]*packTableItem, error) {
	// Unzip in memory (the max request size is only 6 MB, so this should easily fit)
	zipReader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("zipReader failed: %s", err)
	}
	var packs map[string]*packTableItem
	// Process the zip file and extract each pack file
	for _, zipFile := range zipReader.File {
		unzippedBytes, err := readZipFile(zipFile)
		if err != nil {
			return nil, fmt.Errorf("file extraction failed: %s: %s", zipFile.Name, err)
		}
		// only extract the pack directory
		if !strings.Contains(zipFile.Name, "packs/") {
			continue
		}

		var config analysis.PackConfig

		switch strings.ToLower(filepath.Ext(zipFile.Name)) {
		case ".yml", ".yaml":
			err = yaml.Unmarshal(unzippedBytes, &config)
		default:
			zap.L().Debug("skipped unsupported file", zap.String("fileName", zipFile.Name))
		}

		if err != nil {
			return nil, err
		}

		// Map the Config struct fields over to the fields we need to store in Dynamo
		analysisPackItem := packTableItemFromConfig(config)

		if _, exists := packs[analysisPackItem.ID]; exists {
			return nil, fmt.Errorf("multiple pack specs with ID %s", analysisPackItem.ID)
		}
		packs[analysisPackItem.ID] = analysisPackItem
	}

	return packs, nil
}

func packTableItemFromConfig(config analysis.PackConfig) *packTableItem {
	item := packTableItem{
		Description: config.Description,
		DisplayName: config.DisplayName,
		ID:          config.PackID,
		Type:        models.DetectionType(strings.ToUpper(config.AnalysisType)),
	}
	var detectionPattern models.DetectionPattern
	if config.DetectionPattern.IDs != nil {
		detectionPattern.IDs = config.DetectionPattern.IDs
	}
	item.DetectionPattern = detectionPattern
	return &item
}

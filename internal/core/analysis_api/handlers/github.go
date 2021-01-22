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
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/google/go-github/github"
	"github.com/hashicorp/go-version"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/api/lambda/analysis"
	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/awsutils"
)

const (
	// github org and repo containing detection packs
	pantherGithubOwner = "panther-labs"
	pantherGithubRepo  = "panther-analysis"
	// signing keys information
	pantherFirstSigningKeyID = "2f555f7a-636a-41ed-9a6b-c6192bf55810" // TODO: update: this is a test key
	signingAlgorithm         = kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512
	// source filenames
	pantherSourceFilename    = "panther-analysis-all.zip"
	pantherSignatureFilename = "panther-analysis-all.sig"
	// cache the detection packs to prevent downloading them multiple times
	// when updating packs (potentially one at a time) via the UI
	cacheTimeout = 15 * time.Minute
	// minimum version that supports packs
	minimumVersionName = "v1.15.0"
)

var (
	// cache packs and detections
	cacheLastUpdated time.Time
	cacheVersion     models.Version
	detectionCache   = make(map[string]*tableItem)
	packCache        = make(map[string]*packTableItem)
)

func downloadGithubAsset(id int64) ([]byte, error) {
	rawAsset, url, err := githubClient.Repositories.DownloadReleaseAsset(context.Background(), pantherGithubOwner, pantherGithubRepo, id)
	// download the raw data
	var body []byte
	if rawAsset != nil {
		body, err = ioutil.ReadAll(rawAsset)
		rawAsset.Close()
	} else if url != "" {
		body, err = downloadURL(url)
	}
	return body, err
}

func downloadGithubRelease(version models.Version) (sourceData []byte, signatureData []byte, err error) {
	// Setup options and client
	// First, get all of the release data
	release, _, err := githubClient.Repositories.GetRelease(context.Background(), pantherGithubOwner, pantherGithubRepo, version.ID)
	if err != nil {
		return nil, nil, err
	}
	// retrieve the signature file and entire analysis zip
	for _, asset := range release.Assets {
		if *asset.Name == pantherSignatureFilename {
			signatureData, err = downloadGithubAsset(*asset.ID)
		} else if *asset.Name == pantherSourceFilename {
			sourceData, err = downloadGithubAsset(*asset.ID)
		}
		if err != nil {
			// If we failed to download an asset, report and return the error
			zap.L().Error("Failed to download release asset file from repo",
				zap.String("sourceFile", *asset.Name),
				zap.String("repository", pantherGithubRepo))
			return nil, nil, err
		}
	}
	return sourceData, signatureData, nil
}

func downloadURL(url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("url is not https: %v", url)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	response, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to GET %s: %v", url, err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %v", url, err)
	}
	return body, nil
}

func downloadValidatePackData(version models.Version) error {
	sourceData, signatureData, err := downloadGithubRelease(version)
	if err != nil || sourceData == nil || signatureData == nil {
		zap.L().Error("GitHub release version download failed",
			zap.Error(err),
			zap.Bool("sourceData nil", sourceData == nil),
			zap.Bool("signatureData nil", signatureData == nil))
		return err
	}
	err = validateSignature(sourceData, signatureData)
	if err != nil {
		return err
	}
	packCache, detectionCache, err = extractPackZipFileBytes(sourceData)
	if err != nil {
		zap.L().Error("error extracting pack data", zap.Error(err))
		return err
	}
	cacheLastUpdated = time.Now()
	cacheVersion = version
	return nil
}

func extractPackZipFileBytes(content []byte) (map[string]*packTableItem, map[string]*tableItem, error) {
	// Unzip in memory
	zipReader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, nil, fmt.Errorf("zipReader failed: %s", err)
	}
	packs := make(map[string]*packTableItem)
	detections := make(map[string]*tableItem)
	detectionBodies := make(map[string]string) // map base file name to contents

	// Process the zip file and extract each pack file
	for _, zipFile := range zipReader.File {
		unzippedBytes, err := readZipFile(zipFile)
		if err != nil {
			return nil, nil, fmt.Errorf("file extraction failed: %s: %s", zipFile.Name, err)
		}
		// the pack directory
		if strings.Contains(zipFile.Name, "packs/") {
			var config analysis.PackConfig

			switch strings.ToLower(filepath.Ext(zipFile.Name)) {
			case ".yml", ".yaml":
				err = yaml.Unmarshal(unzippedBytes, &config)
			default:
				zap.L().Debug("skipped unsupported file", zap.String("fileName", zipFile.Name))
				continue
			}

			if err != nil {
				return nil, nil, err
			}

			// Map the Config struct fields over to the fields we need to store in Dynamo
			analysisPackItem := packTableItemFromConfig(config)
			if _, exists := packs[analysisPackItem.ID]; exists {
				return nil, nil, fmt.Errorf("multiple pack specs with ID %s", analysisPackItem.ID)
			}
			packs[analysisPackItem.ID] = analysisPackItem
		} else {
			var config analysis.Config

			switch strings.ToLower(filepath.Ext(zipFile.Name)) {
			case ".py":
				// Store the Python body to be referenced later
				detectionBodies[filepath.Base(zipFile.Name)] = string(unzippedBytes)
				continue
			case ".json":
				err = jsoniter.Unmarshal(unzippedBytes, &config)
			case ".yml", ".yaml":
				err = yaml.Unmarshal(unzippedBytes, &config)
			default:
				zap.L().Debug("skipped unsupported file", zap.String("fileName", zipFile.Name))
			}

			if err != nil {
				return nil, nil, err
			}

			// Map the Config struct fields over to the fields we need to store in Dynamo
			analysisItem := tableItemFromConfig(config)
			if analysisItem.Type == models.TypeDataModel && len(config.Mappings) > 0 {
				// ensure Mappings are nil rather than an empty slice
				analysisItem.Mappings = make([]models.DataModelMapping, len(config.Mappings))
				for i, mapping := range config.Mappings {
					analysisItem.Mappings[i], err = buildMapping(mapping)
					if err != nil {
						return nil, nil, err
					}
				}
			}

			for i, test := range config.Tests {
				// A test can specify a resource and a resource type or a log and a log type.
				// By convention, log and log type are used for rules and resource and resource type are used for policies.
				if test.Resource == nil {
					analysisItem.Tests[i], err = buildRuleTest(test)
				} else {
					analysisItem.Tests[i], err = buildPolicyTest(test)
				}
				if err != nil {
					return nil, nil, err
				}
			}

			if _, exists := detections[analysisItem.ID]; exists {
				return nil, nil, fmt.Errorf("multiple analysis specs with ID %s", analysisItem.ID)
			}
			detections[analysisItem.ID] = analysisItem
		}
	}

	// add python bodies
	// Finish each detection by adding its body and then validate it
	for _, detection := range detections {
		if body, ok := detectionBodies[detection.Body]; ok {
			detection.Body = body
			if err := validateUploadedPolicy(detection); err != nil {
				return nil, nil, err
			}
		} else if detection.Type != models.TypeDataModel {
			// it is ok for DataModels to be missing python body
			return nil, nil, fmt.Errorf("policy %s is missing a body", detection.ID)
		}
	}

	return packs, detections, err
}

func listAvailableGithubReleases() ([]models.Version, error) {
	// Setup options
	// By default returns all releases, paged at 100 releases at a time
	opt := &github.ListOptions{}
	var allReleases []*github.RepositoryRelease
	for {
		releases, response, err := githubClient.Repositories.ListReleases(context.Background(), pantherGithubOwner, pantherGithubRepo, opt)
		if err != nil {
			return nil, err
		}
		allReleases = append(allReleases, releases...)
		if response.NextPage == 0 {
			break
		}
		opt.Page = response.NextPage
	}
	var availableVersions []models.Version
	// earliest version of panther managed detections that supports packs
	minimumVersion, _ := version.NewVersion(minimumVersionName)
	for _, release := range allReleases {
		version, err := version.NewVersion(*release.Name)
		if err != nil {
			// if we can't parse the version, just throw it away
			zap.L().Warn("can't parse version", zap.String("version", *release.Name))
			continue
		}
		if version.GreaterThan(minimumVersion) {
			newVersion := models.Version{
				ID:   *release.ID,
				Name: *release.Name,
			}
			availableVersions = append(availableVersions, newVersion)
		}
	}
	return availableVersions, nil
}

func validateSignature(rawData []byte, signature []byte) error {
	// use hash of body in validation
	intermediateHash := sha512.Sum512(rawData)
	var computedHash []byte = intermediateHash[:]
	// The signature is base64 encoded in the file, decode it
	decodedSignature, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		zap.L().Error("error base64 decoding item", zap.Error(err))
		return err
	}
	signatureVerifyInput := &kms.VerifyInput{
		KeyId:            aws.String(pantherFirstSigningKeyID),
		Message:          computedHash,
		MessageType:      aws.String(kms.MessageTypeDigest),
		Signature:        decodedSignature,
		SigningAlgorithm: aws.String(signingAlgorithm),
	}
	result, err := kmsClient.Verify(signatureVerifyInput)
	if err != nil {
		if awsutils.IsAnyError(err, kms.ErrCodeKMSInvalidSignatureException) {
			zap.L().Error("signature verification failed", zap.Error(err))
			return err
		}
		zap.L().Warn("error validating signature", zap.Error(err))
		return err
	}
	if *result.SignatureValid {
		zap.L().Debug("signature validation successful")
		return nil
	}
	return errors.New("error validating signature")
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

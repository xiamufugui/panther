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
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/google/go-github/github"
	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"go.uber.org/zap"
)

type ReleaseAsset struct {
	Contents  []byte
	Signature []byte
}

var (
	github_owner = "panther-labs"
	github_repo  = "panther-analysis"
)

func (API) PollPacks(input *models.PollPacksInput) *events.APIGatewayProxyResponse {
	// First, retrieve & validate all the packs in the panther-analysis repo

	// Second, lookup existing item values to determine if updates are available
	items, err := getPackItems(&dynamodb.ScanInput{
		TableName: &env.PackTable,
	})
	if err != nil {
		// error looking up the existing pack data
		zap.L().Error("failed to scan panther-analysis-pack table", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	currentPacks := make([]models.Pack, len(items))
	for _, item := range items {
		currentPacks = append(currentPacks, *item.Pack())
	}
	// Finally, loop through each pack and CHECK if update is available / create a new pack:
	// update fields: availableReleases and updateAvailable status of the detections in the pack
	// AND create any _new_ packs (default to disabled status)

	// Report success
	return gatewayapi.MarshalResponse(nil, http.StatusOK)
}

func downloadValidatePackData() {
	var releaseID int64
	releaseID = 12345
	releaseAssests, err := downloadGithubRelease(models.Release{ID: releaseID})
	if err != nil {
		//TODO
		fmt.Println("Hello")
	}

}

func downloadGithubRelease(releaseVersion models.Release) ([]ReleaseAsset, error) {
	// Setup options and client
	client := github.NewClient(nil)
	// First, get all of the release data
	release, _, err := client.Repositories.GetRelease(context.Background(), github_owner, github_repo, releaseVersion.ID)
	if err != nil {
		return nil, err
	}
	// setup variables for pulling in source code and signature files
	// this expects that for each file in the configured source, there is an
	// associated filename.sig file
	sourceAssets := make(map[string]*int64)
	signatureAssets := make(map[string]*int64)
	var downloadedAssets []ReleaseAsset
	for _, asset := range release.Assets {
		if filepath.Ext(*asset.Name) == ".sig" {
			signatureAssets[filepath.Base(*asset.Name)] = asset.ID
		} else {
			sourceAssets[filepath.Base(*asset.Name)] = asset.ID
		}
	}
	for assetName, sourceID := range sourceAssets {
		if signatureID, ok := signatureAssets[assetName]; ok {
			// only need to retrieve data for file that also have a signature
			signatureData, err := getGithubAsset(client, *signatureID)
			if err != nil {
				// no need to download the source file if the signature file fails to download
				zap.L().Warn("Failed to download signature file from repo",
					zap.String("signature_file", assetName))
				continue
			}
			sourceData, err := getGithubAsset(client, *sourceID)
			if err != nil {
				// If we failed to download the asset, don't add anything to downloadedAssets
				zap.L().Warn("Failed to download source file from repo",
					zap.String("source_file", assetName),
					zap.String("repository", github_repo))
				continue
			}
			newAsset := ReleaseAsset{
				Signature: signatureData,
				Contents:  sourceData,
			}
			downloadedAssets = append(downloadedAssets, newAsset)
		} else {
			// There was a source asset that doesn't have an associated signature file
			// TODO: downgrade this to 'info' or 'debug' as this shouldn't be an issue
			zap.L().Warn("Github asset in repo is missing an associated signature file",
				zap.String("source_file", assetName),
				zap.String("repository", github_repo))
		}
	}

	return downloadedAssets, nil
}

func getGithubAsset(client *github.Client, id int64) ([]byte, error) {
	rawAsset, _, err := client.Repositories.DownloadReleaseAsset(context.Background(), github_owner, github_repo, id)
	// download the raw data
	var body []byte
	if rawAsset != nil {
		body, err = ioutil.ReadAll(rawAsset)
		rawAsset.Close()
	}
	return body, err
}

func listAvailableGithubReleases() ([]models.Release, error) {
	// Setup options and client
	// TODO: should number of available releases be configurable? By default returns all releases
	// by default, will page at 100 releases at a time
	opt := &github.ListOptions{}
	client := github.NewClient(nil)
	var allReleases []*github.RepositoryRelease
	for {
		releases, response, err := client.Repositories.ListReleases(context.Background(), github_owner, github_repo, opt)
		if err != nil {
			return nil, err
		}
		allReleases = append(allReleases, releases...)
		if response.NextPage == 0 {
			break
		}
		opt.Page = response.NextPage
	}
	availableReleases := make([]models.Release, 10)
	for i, release := range allReleases {
		// TODO: should this filter out releases that don't have pack manifests here?
		availableReleases[i].DisplayName = *release.Name
		availableReleases[i].ID = *release.ID
	}
	return availableReleases, nil
}

func validateSignature512(publicKey string, rawData []byte, signature []byte) error {
	// first, compute the hash from rawData
	intermediateHash := sha512.Sum512(rawData)
	var computedHash []byte = intermediateHash[:]
	// convert str version of public key to rsa
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return errors.New("could not decode public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pubKey := key.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, computedHash, signature)
	if err != nil {
		return err
	}
	// Successfully verified message with signature and public key; return
	return nil
}

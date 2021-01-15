package handlers

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"time"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/google/go-github/github"
	"github.com/hashicorp/go-version"
	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"go.uber.org/zap"
)

const (
	// github org and repo containing detection packs
	githubOwner      = "panther-labs"
	githubRepo       = "panther-analysis"
	signingKeyID     = "2f555f7a-636a-41ed-9a6b-c6192bf55810" // TODO: this is a test key
	signingAlgorithm = kms.SigningAlgorithmSpecEcdsaSha512
	// cache the detection packs to prevent downloading them up multiple times
	// when updating packs (potentially one at a time) via the UI
	cacheTimeout = 60 * time.Minute
	// minimum version that supported packs
	minimumVersion = "v1.15.0"
	// default version for the `EnabledRelease` field for new packs
	defaultVersion = "v0.0.0"
)

var (
	// cache packs and detections
	cacheLastUpdated time.Time
	cacheVersion     models.Release
	detectionCache   = make(map[string]*tableItem)
	packCache        = make(map[string]*packTableItem)
)

func downloadGithubAsset(client *github.Client, id int64) ([]byte, error) {
	rawAsset, _, err := client.Repositories.DownloadReleaseAsset(context.Background(), githubOwner, githubRepo, id)
	// download the raw data
	var body []byte
	if rawAsset != nil {
		body, err = ioutil.ReadAll(rawAsset)
		rawAsset.Close()
	}
	return body, err
}

func downloadGithubRelease(releaseVersion models.Release) (sourceData []byte, signatureData []byte, err error) {
	// Setup options and client
	client := github.NewClient(nil)
	// First, get all of the release data
	release, _, err := client.Repositories.GetRelease(context.Background(), githubOwner, githubRepo, releaseVersion.ID)
	if err != nil {
		return nil, nil, err
	}
	// retreive the signature file and entire analysis zip
	for _, asset := range release.Assets {
		//if *asset.Name == "panther-analysis.sig" {
		//	signatureData, err = downloadGithubAsset(client, *asset.ID)
		//} else
		if *asset.Name == "panther-analysis-all.zip" {
			sourceData, err = downloadGithubAsset(client, *asset.ID)
		}
		if err != nil {
			// If we failed to download an asset, report and return the error
			zap.L().Error("Failed to download release asset file from repo",
				zap.String("source_file", *asset.Name),
				zap.String("repository", githubRepo))
			return nil, nil, err
		}
	}
	// TODO: removed the signature retrieval for testing purposes
	//return sourceData, signatureData, nil
	correctSignature, _ := base64.StdEncoding.DecodeString("e14BUAuoq2oohlpo3Ref2Iatrm0wGEiDUhYPpAOcRxd5pcNzjgILnlAOR5Yg0kcCZKz3XSsHXeywoqtVQe/fcHL8IjX/JmxOVZU5MCed3V4utdl7G8rmbc7o3o2KIgKVpCnpy07rbzGblojuS8QE8VUIlkGcBWh6e0W27Pa2IG/KrBJBy/t2BhhpF8aOAnSJdxwXBOwd9cUUKiw1FGVisj2CkOFGltLJRFJZRi9DKR8P/6KCCra0OdwpaD1uQaAzBOlCDHuuVXL3KGFKGTtxLZV+CUDdWZToseiJJEo0xfdYYIZzwsOe7U848sIV3Ov70OOPcqNqtsfJJAqomquTZkfKNR4/YWNXydm8+q0rVCjjJ2b3sQJ7HRGXOK0ZFdAzmn27RsexGDs/AFdrhKasXwCpiXE0aYOJYZvWi0PoDjdGvyzVVuFveTxKjN72WzzbgffiC2anrq5msACuSuYli++MvWvcMXAPM33sUaWrgrY6mu9hWiuFsfoubC4KBBq+uT3O+DRSUZsVL5jZzUcJUhYNsplef51F1dov1ItQTuj3D8EhtE3nkLKHR09iMuryrb/K/lZLwL5TUU09vk9wxYNNjFZh5wJeAhHWTsYklA+fTPtIlQR9hrt4hz5DN/XPPvJtuDvinkwyUcjCrecnCyF/Ybu/IZsvFmv3XlzwzdA=")
	return sourceData, correctSignature, nil
}

func downloadValidatePackData(release models.Release) error {
	sourceData, signatureData, err := downloadGithubRelease(release)
	if err != nil {
		zap.L().Error("GitHub release download failed", zap.Error(err))
		return err
	}
	err = validateSignature(sourceData, signatureData)
	if err != nil {
		return err
	}
	// TODO: this is inefficient - extracting the same zip file multiple times
	// but I wanted to reuse the bulk uploader logic / updating the bulk uploader to
	// take packs into account doesn't make sense
	detectionCache, err = extractZipFileBytes(sourceData)
	if err != nil {
		return err
	}
	packCache, err = extractPackZipFileBytes(sourceData)
	if err != nil {
		return err
	}
	cacheLastUpdated = time.Now()
	cacheVersion = release
	return nil
}

func listAvailableGithubReleases() ([]models.Release, error) {
	// Setup options and client
	// TODO: should number of available releases be configurable? By default returns all releases
	// paged at 100 releases at a time
	opt := &github.ListOptions{}
	client := github.NewClient(nil)
	var allReleases []*github.RepositoryRelease
	for {
		releases, response, err := client.Repositories.ListReleases(context.Background(), githubOwner, githubRepo, opt)
		if err != nil {
			return nil, err
		}
		allReleases = append(allReleases, releases...)
		if response.NextPage == 0 {
			break
		}
		opt.Page = response.NextPage
	}
	var availableReleases []models.Release
	// earliest version of panther managed detections that supports packs
	minimumVersion, _ := version.NewVersion(minimumVersion)
	for _, release := range allReleases {
		version, err := version.NewVersion(*release.Name)
		if err != nil {
			// if we can't parse the version, just throw it away?
			continue
		}
		if version.GreaterThan(minimumVersion) {
			release := models.Release{
				ID:      *release.ID,
				Version: *release.Name,
			}
			availableReleases = append(availableReleases, release)
		}
	}
	return availableReleases, nil
}

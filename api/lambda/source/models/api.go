package models

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

import "time"

// LambdaInput is the collection of all possible args to the Lambda function.
type LambdaInput struct {
	CheckIntegration *CheckIntegrationInput `json:"integrationHealthCheck"`

	PutIntegration            *PutIntegrationInput            `json:"putIntegration"`
	UpdateIntegrationSettings *UpdateIntegrationSettingsInput `json:"updateIntegrationSettings"`
	ListIntegrations          *ListIntegrationsInput          `json:"listIntegrations"`
	DeleteIntegration         *DeleteIntegrationInput         `json:"deleteIntegration"`

	ListLogTypes *ListLogTypesInput `json:"listLogTypes"`

	GetIntegrationTemplate *GetIntegrationTemplateInput `json:"getIntegrationTemplate"`

	UpdateIntegrationLastScanEnd   *UpdateIntegrationLastScanEndInput   `json:"updateIntegrationLastScanEnd"`
	UpdateIntegrationLastScanStart *UpdateIntegrationLastScanStartInput `json:"updateIntegrationLastScanStart"`

	FullScan     *FullScanInput     `json:"fullScan"`
	UpdateStatus *UpdateStatusInput `json:"updateStatus"`
}

//
// CheckIntegration: Used by the UI to determine integration status
//

// CheckIntegrationInput is used to check the health of a potential configuration.
type CheckIntegrationInput struct {
	AWSAccountID     string `genericapi:"redact" json:"awsAccountId" validate:"omitempty,len=12,numeric"`
	IntegrationType  string `json:"integrationType" validate:"oneof=aws-scan aws-s3 aws-sqs"`
	IntegrationLabel string `json:"integrationLabel" validate:"required,integrationLabel"`

	// Checks for cloudsec integrations
	EnableCWESetup    *bool `json:"enableCWESetup"`
	EnableRemediation *bool `json:"enableRemediation"`

	// Checks for log analysis integrations
	S3Bucket         string           `json:"s3Bucket"`
	S3PrefixLogTypes S3PrefixLogtypes `json:"s3PrefixLogTypes,omitempty"`
	KmsKey           string           `json:"kmsKey"`

	// Checks for Sqs configuration
	SqsConfig *SqsConfig `json:"sqsConfig,omitempty"`
}

//
// PutIntegration: Used by the UI
//

// PutIntegrationInput is used to add one or many integrations.
type PutIntegrationInput struct {
	PutIntegrationSettings
}

// PutIntegrationSettings are all the settings for the new integration.
type PutIntegrationSettings struct {
	IntegrationLabel           string           `json:"integrationLabel" validate:"required,integrationLabel,excludesall='<>&\""`
	IntegrationType            string           `json:"integrationType" validate:"oneof=aws-scan aws-s3 aws-sqs"`
	UserID                     string           `json:"userId" validate:"required,uuid4"`
	AWSAccountID               string           `genericapi:"redact" json:"awsAccountId" validate:"omitempty,len=12,numeric"`
	CWEEnabled                 *bool            `json:"cweEnabled"`
	RemediationEnabled         *bool            `json:"remediationEnabled"`
	ScanIntervalMins           int              `json:"scanIntervalMins" validate:"omitempty,oneof=60 180 360 720 1440"`
	Enabled                    *bool            `json:"enabled"`
	RegionIgnoreList           []string         `json:"regionIgnoreList"`
	ResourceTypeIgnoreList     []string         `json:"resourceTypeIgnoreList"`
	ResourceRegexIgnoreList    []string         `json:"resourceRegexIgnoreList"`
	S3Bucket                   string           `json:"s3Bucket"`
	S3PrefixLogTypes           S3PrefixLogtypes `json:"s3PrefixLogTypes,omitempty" validate:"omitempty,min=1"`
	KmsKey                     string           `json:"kmsKey" validate:"omitempty,kmsKeyArn"`
	ManagedBucketNotifications bool             `json:"managedBucketNotifications"`

	SqsConfig *SqsConfig `json:"sqsConfig,omitempty"`
}

//
// ListIntegrations: Used by the Scheduler to find integrations to scan
//

// ListIntegrationsInput allows filtering by the IntegrationType field
type ListIntegrationsInput struct {
	IntegrationType *string `json:"integrationType" validate:"omitempty,oneof=aws-scan aws-s3 aws-sqs"`
}

// UpdateIntegrationSettingsInput is used to update integration settings.
type UpdateIntegrationSettingsInput struct {
	IntegrationID           string           `json:"integrationId" validate:"required,uuid4"`
	IntegrationLabel        string           `json:"integrationLabel" validate:"required,integrationLabel,excludesall='<>&\""`
	CWEEnabled              *bool            `json:"cweEnabled"`
	RemediationEnabled      *bool            `json:"remediationEnabled"`
	ScanIntervalMins        int              `json:"scanIntervalMins" validate:"omitempty,oneof=60 180 360 720 1440"`
	Enabled                 *bool            `json:"enabled"`
	RegionIgnoreList        []string         `json:"regionIgnoreList"`
	ResourceTypeIgnoreList  []string         `json:"resourceTypeIgnoreList"`
	ResourceRegexIgnoreList []string         `json:"resourceRegexIgnoreList"`
	S3Bucket                string           `json:"s3Bucket" validate:"omitempty,min=1"`
	S3PrefixLogTypes        S3PrefixLogtypes `json:"s3PrefixLogTypes,omitempty" validate:"omitempty,min=1"`
	KmsKey                  string           `json:"kmsKey" validate:"omitempty,kmsKeyArn"`

	SqsConfig *SqsConfig `json:"sqsConfig,omitempty"`
}

// DeleteIntegrationInput is used to delete a specific item from the database.
type DeleteIntegrationInput struct {
	IntegrationID string `json:"integrationId" validate:"required,uuid4"`
}

//
// ListLogTypes: used to get full list of distinct logType over all integrations
//

// ListLogTypesInput
type ListLogTypesInput struct {
}

// ListLogTypesOutput
type ListLogTypesOutput struct {
	LogTypes []string `json:"logTypes" validate:"omitempty"`
}

//
// FullScan: Used by the Scheduler to scan integrations
//

// FullScanInput is used to do a full scan of one or more integrations.
type FullScanInput struct {
	Integrations []*SourceIntegrationMetadata
}

//
// GetIntegrationTemplate: Used by the frontend to provide templates for users
//

// GetIntegrationTemplateInput allows specification of what resources should be enabled/disabled in the template
type GetIntegrationTemplateInput struct {
	AWSAccountID               string   `genericapi:"redact" json:"awsAccountId" validate:"required,len=12,numeric"`
	IntegrationType            string   `json:"integrationType" validate:"oneof=aws-scan aws-s3"`
	IntegrationLabel           string   `json:"integrationLabel" validate:"required,integrationLabel"`
	RemediationEnabled         *bool    `json:"remediationEnabled"`
	CWEEnabled                 *bool    `json:"cweEnabled"`
	Enabled                    *bool    `json:"enabled" validate:"omitempty"`
	RegionIgnoreList           []string `json:"regionIgnoreList" validate:"omitempty"`
	ResourceTypeIgnoreList     []string `json:"resourceTypeIgnoreList" validate:"omitempty"`
	ResourceRegexIgnoreList    []string `json:"resourceRegexIgnoreList" validate:"omitempty"`
	S3Bucket                   string   `json:"s3Bucket" validate:"omitempty,min=1"`
	KmsKey                     string   `json:"kmsKey" validate:"omitempty,kmsKeyArn"`
	ManagedBucketNotifications bool     `json:"managedBucketNotifications"`
}

//
// UpdateIntegration: Used by the UI
//

// UpdateIntegrationLastScanStartInput is used to update scan information at the beginning of a scan.
type UpdateIntegrationLastScanStartInput struct {
	IntegrationID     string    `json:"integrationId" validate:"required,uuid4"`
	LastScanStartTime time.Time `json:"lastScanStartTime" validate:"required"`
	ScanStatus        string    `json:"scanStatus" validate:"required,oneof=ok error scanning"`
}

// UpdateIntegrationLastScanEndInput is used to update scan information at the end of a scan.
type UpdateIntegrationLastScanEndInput struct {
	ScanStatus           string    `json:"scanStatus" validate:"oneof=ok error scanning"`
	IntegrationID        string    `json:"integrationId" validate:"required,uuid4"`
	LastScanEndTime      time.Time `json:"lastScanEndTime" validate:"required"`
	EventStatus          string    `json:"eventStatus"`
	LastScanErrorMessage string    `json:"lastScanErrorMessage"`
}

// Updates the status of an integration
// Sample request:
// {
//	"updateStatus": {
// 		"integrationId": "uuid",
//		"lastEventReceived":"2020-10-10T05:03:01Z"
// 	}
// }
//
type UpdateStatusInput struct {
	IntegrationID     string    `json:"integrationId" validate:"required,uuid4"`
	LastEventReceived time.Time `json:"lastEventReceived" validate:"required"`
}

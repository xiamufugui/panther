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

const (
	// Status is OK
	StatusOK = "OK"
	// Status is Error
	StatusError = "ERROR"
)

type Component string

const (
	ComponentDataSources    = "DataSources"
	ComponentClassification = "Classification"
	ComponentDetections     = "Detections"
	ComponentDatalake       = "Datalake"
	ComponentAlertDelivery  = "AlertDelivery"
)

// LambdaInput is the collection of all possible args to the Lambda function.
type LambdaInput struct {
	// get the status of all system components.
	GetSystemStatus *GetSystemStatusInput `json:"getSystemStatus"`
}

// GetSystemStatusInput
type GetSystemStatusInput struct {
}

// GetSystemStatusOutput is the response of the System status
//{
//	"Datalake":{
//		"status":"OK"
//},
//	"DataSources":{
//		"status":"ERROR",
//		"message":"Sources failing, please visiting sources page for details",
//		"redirectUrl":"https://web-710238182.us-east-1.elb.amazonaws.com/log-analysis/sources"
//	},
//	"Classification":{
//		"status":"OK"
//	},
//	"Detections":{
//		"status":"OK"
//	},
//	"AlertDelivery":{
//		"status":"OK"
//	}
//}
type GetSystemStatusOutput map[Component]ComponentStatus

type ComponentStatus struct {
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
	Redirect string `json:"redirectUrl,omitempty"`
}

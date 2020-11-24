package forwarder

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
	"crypto/md5" // nolint: gosec
	"encoding/hex"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/delivery/models"
	alertModel "github.com/panther-labs/panther/internal/log_analysis/alert_forwarder/forwarder"
	"github.com/panther-labs/panther/pkg/metrics"
)

const defaultTimePartition = "defaultPartition"

type Handler struct {
	SqsClient        sqsiface.SQSAPI
	DdbClient        dynamodbiface.DynamoDBAPI
	AlertTable       string
	AlertingQueueURL string
	MetricsLogger    metrics.Logger
}

func (h *Handler) Do(alert models.Alert) error {
	// Creates an ID and sets it in the alert
	alert.AlertID = GenerateAlertID(alert)

	// Persist to DDB
	if err := h.storeNewAlert(alert); err != nil {
		return errors.Wrap(err, "failed to store new alert (policy) in DDB")
	}

	// Send to Dispatch queue
	if err := h.sendAlertNotification(alert); err != nil {
		return err
	}

	// Log stats
	if alert.Type == models.PolicyType {
		h.logStats(alert)
	}

	return nil
}

func getAlertTypeForLog(alert models.Alert) string {
	alertType := ""
	switch alert.Type {
	case models.PolicyType:
		alertType = "Policy"
	case models.RuleType:
		alertType = "Rule"
	case models.RuleErrorType:
		alertType = "Rule_Error"
	default:
		zap.L().Error("Invalid Alert type")
	}
	return alertType
}

func (h *Handler) logStats(alert models.Alert) {
	h.MetricsLogger.Log(
		[]metrics.Dimension{
			{Name: "Severity", Value: alert.Severity},
			{Name: "AnalysisType", Value: getAlertTypeForLog(alert)},
			{Name: "AnalysisID", Value: alert.AnalysisID},
		},
		metrics.Metric{
			Name:  "AlertsCreated",
			Value: 1,
			Unit:  metrics.UnitCount,
		},
	)
}

func (h *Handler) storeNewAlert(alert models.Alert) error {
	// Here we re-use the same field names for alerts that were
	// generated from rules.
	dynamoAlert := &alertModel.Alert{
		ID:                  *alert.AlertID,
		TimePartition:       defaultTimePartition,
		Severity:            alert.Severity,
		RuleDisplayName:     alert.AnalysisName,
		Title:               aws.StringValue(alert.Title),
		FirstEventMatchTime: alert.CreatedAt,
		ResourceTypes:       alert.ResourceTypes,
		ResourceID:          alert.ResourceID,
		AlertDedupEvent: alertModel.AlertDedupEvent{
			RuleID: alert.AnalysisID,
			// RuleVersion: *alert.Version, //FIXME: we need to grab the policy that triggered this alert
			// DeduplicationString: alert.DeduplicationString, // Policies don't have this
			CreationTime: alert.CreatedAt,
			UpdateTime:   alert.CreatedAt,
			EventCount:   1,
			LogTypes:     alert.LogTypes,
			Type:         alert.Type,
		},
	}

	marshaledAlert, err := dynamodbattribute.MarshalMap(dynamoAlert)
	if err != nil {
		return errors.Wrap(err, "failed to marshal alert")
	}
	putItemRequest := &dynamodb.PutItemInput{
		Item:      marshaledAlert,
		TableName: &h.AlertTable,
	}
	_, err = h.DdbClient.PutItem(putItemRequest)
	if err != nil {
		return errors.Wrap(err, "failed to store alert")
	}

	return nil
}

func (h *Handler) sendAlertNotification(alert models.Alert) error {
	msgBody, err := jsoniter.MarshalToString(alert)
	if err != nil {
		return errors.Wrap(err, "failed to marshal alert notification")
	}

	input := &sqs.SendMessageInput{
		QueueUrl:    &h.AlertingQueueURL,
		MessageBody: &msgBody,
	}
	_, err = h.SqsClient.SendMessage(input)
	if err != nil {
		return errors.Wrap(err, "failed to send notification")
	}
	return nil
}

// Generates an ID from the policyID (policy name) and the current timestamp.
// We do not have control over any dedup strings so we use a timestamp for
// differentiation.
func GenerateAlertID(alert models.Alert) *string {
	key := alert.AnalysisID + ":" + alert.CreatedAt.String()
	keyHash := md5.Sum([]byte(key)) // nolint(gosec)
	encoded := hex.EncodeToString(keyHash[:])
	return &encoded
}

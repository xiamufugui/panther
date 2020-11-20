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
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/panther-labs/panther/api/lambda/delivery/models"
	alertModel "github.com/panther-labs/panther/internal/log_analysis/alert_forwarder/forwarder"
	"github.com/panther-labs/panther/pkg/metrics"
	"github.com/panther-labs/panther/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockRoundTripper struct {
	http.RoundTripper
	mock.Mock
}

func (m *mockRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	args := m.Called(request)
	return args.Get(0).(*http.Response), args.Error(1)
}

var (
	expectedMetric     = []metrics.Metric{{Name: "AlertsCreated", Value: 1, Unit: metrics.UnitCount}}
	expectedDimensions = []metrics.Dimension{
		{Name: "Severity", Value: "INFO"},
		{Name: "AnalysisType", Value: "Policy"},
		{Name: "AnalysisID", Value: "Test.Policy"}}
	timeNow = time.Unix(1581379785, 0) // Set a static time
)

func genSampleAlert() models.Alert {
	return models.Alert{
		CreatedAt:           timeNow,
		AnalysisDescription: aws.String("An alert triggered from a Policy"),
		AnalysisID:          "Test.Policy",
		Version:             aws.String("Some version string"),
		AnalysisName:        aws.String("A test policy to generate alerts"),
		Runbook:             aws.String("Check out our docs!"),
		Severity:            "INFO",
		Tags:                []string{"Tag", "Policy", "AWS"},
		Type:                models.PolicyType,
		LogTypes:            []string{"Log", "Types"},
		// AlertID:             aws.String("14385b7633e698ede7e036dc010c1fb6"), // This is generated dynamically
	}
}

func TestGenerateAlertID(t *testing.T) {
	alert := genSampleAlert()
	alertID := GenerateAlertID(alert)
	assert.Equal(t, *alertID, "14385b7633e698ede7e036dc010c1fb6")
}

func TestHandleStoreAndSendNotification(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}

	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}

	// An alert will not have an AlertID
	expectedAlert := genSampleAlert()

	// Now, we dynamically generate that ID
	expectedAlert.AlertID = GenerateAlertID(expectedAlert)

	// Next, simulate sending to SQS
	expectedMarshaledAlert, err := jsoniter.MarshalToString(expectedAlert)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: &expectedMarshaledAlert,
		QueueUrl:    aws.String("queueUrl"),
	}
	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

	// Then, simulate sending to DDB
	expectedDynamoAlert := &alertModel.Alert{
		ID:                  "14385b7633e698ede7e036dc010c1fb6",
		TimePartition:       "defaultPartition",
		Severity:            "INFO",
		RuleDisplayName:     expectedAlert.AnalysisName,
		Title:               aws.StringValue(expectedAlert.Title),
		FirstEventMatchTime: expectedAlert.CreatedAt,
		AlertDedupEvent: alertModel.AlertDedupEvent{
			RuleID: expectedAlert.AnalysisID,
			// RuleVersion: *expectedAlert.Version, // We don't have this working yet
			// DeduplicationString: alert.DeduplicationString, // Policies don't have this
			CreationTime: expectedAlert.CreatedAt,
			UpdateTime:   expectedAlert.CreatedAt,
			EventCount:   1,
			LogTypes:     expectedAlert.LogTypes,
			Type:         expectedAlert.Type,
		},
	}
	expectedMarshaledDynamoAlert, err := dynamodbattribute.MarshalMap(expectedDynamoAlert)
	assert.NoError(t, err)
	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledDynamoAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()
	assert.NoError(t, handler.Do(expectedAlert))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}

// func TestHandleStoreAndSendNotificationNoRuleDisplayNameNoTitle(t *testing.T) {
// 	t.Parallel()
// 	ddbMock := &testutils.DynamoDBMock{}
// 	sqsMock := &testutils.SqsMock{}
// 	metricsMock := &testutils.LoggerMock{}
// 	mockRoundTripper := &mockRoundTripper{}
// 	httpClient := &http.Client{Transport: mockRoundTripper}
// 	policyConfig := policiesclient.DefaultTransportConfig().
// 		WithHost("host").
// 		WithBasePath("path")
// 	policyClient := policiesclient.NewHTTPClientWithConfig(nil, policyConfig)
// 	handler := &Handler{
// 		AlertTable:       "alertsTable",
// 		AlertingQueueURL: "queueUrl",
// 		Cache:            NewCache(httpClient, policyClient),
// 		DdbClient:        ddbMock,
// 		SqsClient:        sqsMock,
// 		MetricsLogger:    metricsMock,
// 	}

// 	newAlertDedupEventWithoutTitle := &AlertDedupEvent{
// 		RuleID:              oldAlertDedupEvent.RuleID,
// 		RuleVersion:         oldAlertDedupEvent.RuleVersion,
// 		DeduplicationString: oldAlertDedupEvent.DeduplicationString,
// 		AlertCount:          oldAlertDedupEvent.AlertCount + 1,
// 		CreationTime:        time.Now().UTC(),
// 		UpdateTime:          time.Now().UTC().Add(1 * time.Minute),
// 		EventCount:          oldAlertDedupEvent.EventCount,
// 		LogTypes:            oldAlertDedupEvent.LogTypes,
// 		Type:                oldAlertDedupEvent.Type,
// 	}

// 	expectedAlertNotification := &alertModel.Alert{
// 		CreatedAt:           newAlertDedupEventWithoutTitle.UpdateTime,
// 		AnalysisDescription: aws.String(string(testRuleResponse.Description)),
// 		AnalysisID:          newAlertDedupEventWithoutTitle.RuleID,
// 		Version:             aws.String(newAlertDedupEventWithoutTitle.RuleVersion),
// 		Runbook:             aws.String(string(testRuleResponse.Runbook)),
// 		Severity:            string(testRuleResponse.Severity),
// 		Tags:                []string{"Tag"},
// 		Type:                alertModel.RuleType,
// 		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
// 		Title:               aws.String(newAlertDedupEventWithoutTitle.RuleID),
// 	}
// 	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
// 	require.NoError(t, err)
// 	expectedSendMessageInput := &sqs.SendMessageInput{
// 		MessageBody: aws.String(expectedMarshaledAlertNotification),
// 		QueueUrl:    aws.String("queueUrl"),
// 	}

// 	testRuleResponseWithoutDisplayName := &ruleModel.Rule{
// 		ID:          "ruleId",
// 		Description: "Description",
// 		Severity:    "INFO",
// 		Runbook:     "Runbook",
// 		Tags:        []string{"Tag"},
// 	}

// 	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponseWithoutDisplayName, http.StatusOK), nil).Once()
// 	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

// 	expectedAlert := &Alert{
// 		ID:                  "b25dc23fb2a0b362da8428dbec1381a8",
// 		TimePartition:       "defaultPartition",
// 		Severity:            string(testRuleResponse.Severity),
// 		Title:               newAlertDedupEventWithoutTitle.RuleID,
// 		FirstEventMatchTime: newAlertDedupEventWithoutTitle.CreationTime,
// 		LogTypes:            newAlertDedupEvent.LogTypes,
// 		AlertDedupEvent: AlertDedupEvent{
// 			RuleID:              newAlertDedupEventWithoutTitle.RuleID,
// 			RuleVersion:         newAlertDedupEventWithoutTitle.RuleVersion,
// 			LogTypes:            newAlertDedupEventWithoutTitle.LogTypes,
// 			EventCount:          newAlertDedupEventWithoutTitle.EventCount,
// 			AlertCount:          newAlertDedupEventWithoutTitle.AlertCount,
// 			DeduplicationString: newAlertDedupEventWithoutTitle.DeduplicationString,
// 			GeneratedTitle:      newAlertDedupEventWithoutTitle.GeneratedTitle,
// 			UpdateTime:          newAlertDedupEventWithoutTitle.UpdateTime,
// 			CreationTime:        newAlertDedupEventWithoutTitle.UpdateTime,
// 			Type:                newAlertDedupEventWithoutTitle.Type,
// 		},
// 	}

// 	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
// 	assert.NoError(t, err)

// 	expectedPutItemRequest := &dynamodb.PutItemInput{
// 		Item:      expectedMarshaledAlert,
// 		TableName: aws.String("alertsTable"),
// 	}

// 	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
// 	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()

// 	assert.NoError(t, handler.Do(oldAlertDedupEvent, newAlertDedupEventWithoutTitle))

// 	ddbMock.AssertExpectations(t)
// 	sqsMock.AssertExpectations(t)
// 	mockRoundTripper.AssertExpectations(t)
// 	metricsMock.AssertExpectations(t)
// }

// func TestHandleStoreAndSendNotificationNoGeneratedTitle(t *testing.T) {
// 	t.Parallel()
// 	ddbMock := &testutils.DynamoDBMock{}
// 	sqsMock := &testutils.SqsMock{}
// 	metricsMock := &testutils.LoggerMock{}
// 	mockRoundTripper := &mockRoundTripper{}
// 	httpClient := &http.Client{Transport: mockRoundTripper}
// 	policyConfig := policiesclient.DefaultTransportConfig().
// 		WithHost("host").
// 		WithBasePath("path")
// 	policyClient := policiesclient.NewHTTPClientWithConfig(nil, policyConfig)
// 	handler := &Handler{
// 		AlertTable:       "alertsTable",
// 		AlertingQueueURL: "queueUrl",
// 		Cache:            NewCache(httpClient, policyClient),
// 		DdbClient:        ddbMock,
// 		SqsClient:        sqsMock,
// 		MetricsLogger:    metricsMock,
// 	}

// 	expectedAlertNotification := &alertModel.Alert{
// 		CreatedAt:           newAlertDedupEvent.UpdateTime,
// 		AnalysisDescription: aws.String(string(testRuleResponse.Description)),
// 		AnalysisID:          newAlertDedupEvent.RuleID,
// 		Version:             aws.String(newAlertDedupEvent.RuleVersion),
// 		AnalysisName:        aws.String(string(testRuleResponse.DisplayName)),
// 		Runbook:             aws.String(string(testRuleResponse.Runbook)),
// 		Severity:            string(testRuleResponse.Severity),
// 		Tags:                []string{"Tag"},
// 		Type:                newAlertDedupEvent.Type,
// 		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
// 		Title:               aws.String("DisplayName"),
// 	}
// 	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
// 	require.NoError(t, err)
// 	expectedSendMessageInput := &sqs.SendMessageInput{
// 		MessageBody: aws.String(expectedMarshaledAlertNotification),
// 		QueueUrl:    aws.String("queueUrl"),
// 	}

// 	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
// 	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

// 	expectedAlert := &Alert{
// 		ID:                  "b25dc23fb2a0b362da8428dbec1381a8",
// 		TimePartition:       "defaultPartition",
// 		Severity:            string(testRuleResponse.Severity),
// 		RuleDisplayName:     aws.String(string(testRuleResponse.DisplayName)),
// 		Title:               "DisplayName",
// 		FirstEventMatchTime: newAlertDedupEvent.CreationTime,
// 		LogTypes:            newAlertDedupEvent.LogTypes,
// 		AlertDedupEvent: AlertDedupEvent{
// 			RuleID:              newAlertDedupEvent.RuleID,
// 			RuleVersion:         newAlertDedupEvent.RuleVersion,
// 			LogTypes:            newAlertDedupEvent.LogTypes,
// 			Type:                newAlertDedupEvent.Type,
// 			EventCount:          newAlertDedupEvent.EventCount,
// 			AlertCount:          newAlertDedupEvent.AlertCount,
// 			DeduplicationString: newAlertDedupEvent.DeduplicationString,
// 			GeneratedTitle:      newAlertDedupEvent.GeneratedTitle,
// 			UpdateTime:          newAlertDedupEvent.UpdateTime,
// 			CreationTime:        newAlertDedupEvent.UpdateTime,
// 		},
// 	}

// 	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
// 	assert.NoError(t, err)

// 	expectedPutItemRequest := &dynamodb.PutItemInput{
// 		Item:      expectedMarshaledAlert,
// 		TableName: aws.String("alertsTable"),
// 	}

// 	dedupEventWithoutTitle := &AlertDedupEvent{
// 		RuleID:              newAlertDedupEvent.RuleID,
// 		RuleVersion:         newAlertDedupEvent.RuleVersion,
// 		Type:                newAlertDedupEvent.Type,
// 		DeduplicationString: newAlertDedupEvent.DeduplicationString,
// 		AlertCount:          newAlertDedupEvent.AlertCount,
// 		CreationTime:        newAlertDedupEvent.CreationTime,
// 		UpdateTime:          newAlertDedupEvent.UpdateTime,
// 		EventCount:          newAlertDedupEvent.EventCount,
// 		LogTypes:            newAlertDedupEvent.LogTypes,
// 	}

// 	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
// 	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()

// 	assert.NoError(t, handler.Do(oldAlertDedupEvent, dedupEventWithoutTitle))

// 	ddbMock.AssertExpectations(t)
// 	sqsMock.AssertExpectations(t)
// 	mockRoundTripper.AssertExpectations(t)
// 	metricsMock.AssertExpectations(t)
// }

// func TestHandleStoreAndSendNotificationNilOldDedup(t *testing.T) {
// 	t.Parallel()
// 	ddbMock := &testutils.DynamoDBMock{}
// 	sqsMock := &testutils.SqsMock{}
// 	metricsMock := &testutils.LoggerMock{}
// 	mockRoundTripper := &mockRoundTripper{}
// 	httpClient := &http.Client{Transport: mockRoundTripper}
// 	policyConfig := policiesclient.DefaultTransportConfig().
// 		WithHost("host").
// 		WithBasePath("path")
// 	policyClient := policiesclient.NewHTTPClientWithConfig(nil, policyConfig)
// 	handler := &Handler{
// 		AlertTable:       "alertsTable",
// 		AlertingQueueURL: "queueUrl",
// 		Cache:            NewCache(httpClient, policyClient),
// 		DdbClient:        ddbMock,
// 		SqsClient:        sqsMock,
// 		MetricsLogger:    metricsMock,
// 	}

// 	expectedAlertNotification := &alertModel.Alert{
// 		CreatedAt:           newAlertDedupEvent.UpdateTime,
// 		AnalysisDescription: aws.String(string(testRuleResponse.Description)),
// 		AnalysisID:          newAlertDedupEvent.RuleID,
// 		AnalysisName:        aws.String(string(testRuleResponse.DisplayName)),
// 		Version:             aws.String(newAlertDedupEvent.RuleVersion),
// 		Runbook:             aws.String(string(testRuleResponse.Runbook)),
// 		Severity:            string(testRuleResponse.Severity),
// 		Tags:                []string{"Tag"},
// 		Type:                alertModel.RuleType,
// 		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
// 		Title:               newAlertDedupEvent.GeneratedTitle,
// 	}
// 	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
// 	require.NoError(t, err)
// 	expectedSendMessageInput := &sqs.SendMessageInput{
// 		MessageBody: aws.String(expectedMarshaledAlertNotification),
// 		QueueUrl:    aws.String("queueUrl"),
// 	}

// 	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
// 	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

// 	expectedAlert := &Alert{
// 		ID:                  "b25dc23fb2a0b362da8428dbec1381a8",
// 		TimePartition:       "defaultPartition",
// 		Severity:            string(testRuleResponse.Severity),
// 		Title:               aws.StringValue(newAlertDedupEvent.GeneratedTitle),
// 		RuleDisplayName:     aws.String(string(testRuleResponse.DisplayName)),
// 		FirstEventMatchTime: newAlertDedupEvent.CreationTime,
// 		LogTypes:            newAlertDedupEvent.LogTypes,
// 		AlertDedupEvent: AlertDedupEvent{
// 			RuleID:              newAlertDedupEvent.RuleID,
// 			Type:                newAlertDedupEvent.Type,
// 			RuleVersion:         newAlertDedupEvent.RuleVersion,
// 			LogTypes:            newAlertDedupEvent.LogTypes,
// 			EventCount:          newAlertDedupEvent.EventCount,
// 			AlertCount:          newAlertDedupEvent.AlertCount,
// 			DeduplicationString: newAlertDedupEvent.DeduplicationString,
// 			GeneratedTitle:      newAlertDedupEvent.GeneratedTitle,
// 			UpdateTime:          newAlertDedupEvent.UpdateTime,
// 			CreationTime:        newAlertDedupEvent.UpdateTime,
// 		},
// 	}

// 	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
// 	require.NoError(t, err)

// 	expectedPutItemRequest := &dynamodb.PutItemInput{
// 		Item:      expectedMarshaledAlert,
// 		TableName: aws.String("alertsTable"),
// 	}

// 	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
// 	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()

// 	require.NoError(t, handler.Do(nil, newAlertDedupEvent))

// 	ddbMock.AssertExpectations(t)
// 	sqsMock.AssertExpectations(t)
// 	mockRoundTripper.AssertExpectations(t)
// 	metricsMock.AssertExpectations(t)
// }

// func TestHandleUpdateAlert(t *testing.T) {
// 	t.Parallel()
// 	ddbMock := &testutils.DynamoDBMock{}
// 	sqsMock := &testutils.SqsMock{}
// 	metricsMock := &testutils.LoggerMock{}
// 	mockRoundTripper := &mockRoundTripper{}
// 	httpClient := &http.Client{Transport: mockRoundTripper}
// 	policyConfig := policiesclient.DefaultTransportConfig().
// 		WithHost("host").
// 		WithBasePath("path")
// 	policyClient := policiesclient.NewHTTPClientWithConfig(nil, policyConfig)
// 	handler := &Handler{
// 		AlertTable:       "alertsTable",
// 		AlertingQueueURL: "queueUrl",
// 		Cache:            NewCache(httpClient, policyClient),
// 		DdbClient:        ddbMock,
// 		SqsClient:        sqsMock,
// 		MetricsLogger:    metricsMock,
// 	}
// 	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()

// 	dedupEventWithUpdatedFields := &AlertDedupEvent{
// 		RuleID:              newAlertDedupEvent.RuleID,
// 		RuleVersion:         newAlertDedupEvent.RuleVersion,
// 		DeduplicationString: newAlertDedupEvent.DeduplicationString,
// 		AlertCount:          newAlertDedupEvent.AlertCount,
// 		CreationTime:        newAlertDedupEvent.CreationTime,
// 		UpdateTime:          newAlertDedupEvent.UpdateTime.Add(1 * time.Minute),
// 		EventCount:          newAlertDedupEvent.EventCount + 10,
// 		LogTypes:            append(newAlertDedupEvent.LogTypes, "New.Log.Type"),
// 		GeneratedTitle:      newAlertDedupEvent.GeneratedTitle,
// 	}

// 	updateExpression := expression.
// 		Set(expression.Name("eventCount"), expression.Value(aws.Int64(dedupEventWithUpdatedFields.EventCount))).
// 		Set(expression.Name("logTypes"), expression.Value(aws.StringSlice(dedupEventWithUpdatedFields.LogTypes))).
// 		Set(expression.Name("updateTime"), expression.Value(aws.Time(dedupEventWithUpdatedFields.UpdateTime)))
// 	expr, err := expression.NewBuilder().WithUpdate(updateExpression).Build()
// 	require.NoError(t, err)

// 	expectedUpdateItemInput := &dynamodb.UpdateItemInput{
// 		TableName: aws.String("alertsTable"),
// 		Key: map[string]*dynamodb.AttributeValue{
// 			"id": {S: aws.String("b25dc23fb2a0b362da8428dbec1381a8")},
// 		},
// 		UpdateExpression:          expr.Update(),
// 		ExpressionAttributeValues: expr.Values(),
// 		ExpressionAttributeNames:  expr.Names(),
// 	}

// 	ddbMock.On("UpdateItem", expectedUpdateItemInput).Return(&dynamodb.UpdateItemOutput{}, nil)
// 	// We shouldn't log any metric - we are not creating a new Alert
// 	metricsMock.AssertNotCalled(t, "Log")

// 	assert.NoError(t, handler.Do(newAlertDedupEvent, dedupEventWithUpdatedFields))

// 	ddbMock.AssertExpectations(t)
// 	sqsMock.AssertExpectations(t)
// 	mockRoundTripper.AssertExpectations(t)
// 	metricsMock.AssertExpectations(t)
// }

// func TestHandleUpdateAlertDDBError(t *testing.T) {
// 	t.Parallel()
// 	ddbMock := &testutils.DynamoDBMock{}
// 	sqsMock := &testutils.SqsMock{}
// 	metricsMock := &testutils.LoggerMock{}
// 	mockRoundTripper := &mockRoundTripper{}
// 	httpClient := &http.Client{Transport: mockRoundTripper}
// 	policyConfig := policiesclient.DefaultTransportConfig().
// 		WithHost("host").
// 		WithBasePath("path")
// 	policyClient := policiesclient.NewHTTPClientWithConfig(nil, policyConfig)
// 	handler := &Handler{
// 		AlertTable:       "alertsTable",
// 		AlertingQueueURL: "queueUrl",
// 		Cache:            NewCache(httpClient, policyClient),
// 		DdbClient:        ddbMock,
// 		SqsClient:        sqsMock,
// 		MetricsLogger:    metricsMock,
// 	}
// 	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()

// 	dedupEventWithUpdatedFields := &AlertDedupEvent{
// 		RuleID:              newAlertDedupEvent.RuleID,
// 		RuleVersion:         newAlertDedupEvent.RuleVersion,
// 		DeduplicationString: newAlertDedupEvent.DeduplicationString,
// 		AlertCount:          newAlertDedupEvent.AlertCount,
// 		CreationTime:        newAlertDedupEvent.CreationTime,
// 		UpdateTime:          newAlertDedupEvent.UpdateTime.Add(1 * time.Minute),
// 		EventCount:          newAlertDedupEvent.EventCount + 10,
// 		LogTypes:            append(newAlertDedupEvent.LogTypes, "New.Log.Type"),
// 		GeneratedTitle:      newAlertDedupEvent.GeneratedTitle,
// 	}

// 	ddbMock.On("UpdateItem", mock.Anything).Return(&dynamodb.UpdateItemOutput{}, errors.New("error"))
// 	assert.Error(t, handler.Do(newAlertDedupEvent, dedupEventWithUpdatedFields))

// 	ddbMock.AssertExpectations(t)
// 	sqsMock.AssertExpectations(t)
// 	mockRoundTripper.AssertExpectations(t)
// 	metricsMock.AssertExpectations(t)
// }

// func TestHandleShouldNotCreateOrUpdateAlertIfThresholdNotReached(t *testing.T) {
// 	t.Parallel()
// 	ddbMock := &testutils.DynamoDBMock{}
// 	sqsMock := &testutils.SqsMock{}
// 	metricsMock := &testutils.LoggerMock{}
// 	mockRoundTripper := &mockRoundTripper{}
// 	httpClient := &http.Client{Transport: mockRoundTripper}
// 	policyConfig := policiesclient.DefaultTransportConfig().
// 		WithHost("host").
// 		WithBasePath("path")
// 	policyClient := policiesclient.NewHTTPClientWithConfig(nil, policyConfig)
// 	handler := &Handler{
// 		AlertTable:       "alertsTable",
// 		AlertingQueueURL: "queueUrl",
// 		Cache:            NewCache(httpClient, policyClient),
// 		DdbClient:        ddbMock,
// 		SqsClient:        sqsMock,
// 		MetricsLogger:    metricsMock,
// 	}

// 	ruleWithThreshold := &ruleModel.Rule{
// 		ID:          "ruleId",
// 		Description: "Description",
// 		DisplayName: "DisplayName",
// 		Severity:    "INFO",
// 		Runbook:     "Runbook",
// 		Tags:        []string{"Tag"},
// 		Threshold:   1000,
// 	}

// 	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(ruleWithThreshold, http.StatusOK), nil).Once()
// 	assert.NoError(t, handler.Do(oldAlertDedupEvent, newAlertDedupEvent))

// 	ddbMock.AssertExpectations(t)
// 	sqsMock.AssertExpectations(t)
// 	mockRoundTripper.AssertExpectations(t)
// 	metricsMock.AssertExpectations(t)
// }

// func TestHandleShouldCreateAlertIfThresholdNowReached(t *testing.T) {
// 	t.Parallel()
// 	ddbMock := &testutils.DynamoDBMock{}
// 	sqsMock := &testutils.SqsMock{}
// 	metricsMock := &testutils.LoggerMock{}
// 	mockRoundTripper := &mockRoundTripper{}
// 	httpClient := &http.Client{Transport: mockRoundTripper}
// 	policyConfig := policiesclient.DefaultTransportConfig().
// 		WithHost("host").
// 		WithBasePath("path")
// 	policyClient := policiesclient.NewHTTPClientWithConfig(nil, policyConfig)
// 	handler := &Handler{
// 		AlertTable:       "alertsTable",
// 		AlertingQueueURL: "queueUrl",
// 		Cache:            NewCache(httpClient, policyClient),
// 		DdbClient:        ddbMock,
// 		SqsClient:        sqsMock,
// 		MetricsLogger:    metricsMock,
// 	}

// 	ruleWithThreshold := &ruleModel.Rule{
// 		ID:          "ruleId",
// 		Description: "Description",
// 		DisplayName: "DisplayName",
// 		Severity:    "INFO",
// 		Runbook:     "Runbook",
// 		Tags:        []string{"Tag"},
// 		Threshold:   1000,
// 	}

// 	newAlertDedup := &AlertDedupEvent{
// 		RuleID:              oldAlertDedupEvent.RuleID,
// 		Type:                oldAlertDedupEvent.Type,
// 		RuleVersion:         oldAlertDedupEvent.RuleVersion,
// 		DeduplicationString: oldAlertDedupEvent.DeduplicationString,
// 		AlertCount:          oldAlertDedupEvent.AlertCount + 1,
// 		CreationTime:        time.Now().UTC(),
// 		UpdateTime:          time.Now().UTC(),
// 		EventCount:          1001,
// 		LogTypes:            oldAlertDedupEvent.LogTypes,
// 		GeneratedTitle:      oldAlertDedupEvent.GeneratedTitle,
// 	}

// 	ddbMock.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, nil).Once()
// 	sqsMock.On("SendMessage", mock.Anything).Return(&sqs.SendMessageOutput{}, nil).Once()
// 	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()

// 	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(ruleWithThreshold, http.StatusOK), nil).Once()
// 	assert.NoError(t, handler.Do(oldAlertDedupEvent, newAlertDedup))

// 	ddbMock.AssertExpectations(t)
// 	sqsMock.AssertExpectations(t)
// 	mockRoundTripper.AssertExpectations(t)
// 	metricsMock.AssertExpectations(t)
// }

// func TestHandleError(t *testing.T) {
// 	// In case of an RULE_ERROR alert type, behave the same
// 	// but don't log Severity metric
// 	t.Parallel()
// 	ddbMock := &testutils.DynamoDBMock{}
// 	sqsMock := &testutils.SqsMock{}
// 	metricsMock := &testutils.LoggerMock{}
// 	mockRoundTripper := &mockRoundTripper{}
// 	httpClient := &http.Client{Transport: mockRoundTripper}
// 	policyConfig := policiesclient.DefaultTransportConfig().
// 		WithHost("host").
// 		WithBasePath("path")
// 	policyClient := policiesclient.NewHTTPClientWithConfig(nil, policyConfig)
// 	handler := &Handler{
// 		AlertTable:       "alertsTable",
// 		AlertingQueueURL: "queueUrl",
// 		Cache:            NewCache(httpClient, policyClient),
// 		DdbClient:        ddbMock,
// 		SqsClient:        sqsMock,
// 		MetricsLogger:    metricsMock,
// 	}

// 	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
// 	sqsMock.On("SendMessage", mock.Anything).Return(&sqs.SendMessageOutput{}, nil)
// 	ddbMock.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, nil)
// 	metricsMock.AssertNotCalled(t, "LogSingle")

// 	oldErrorDedupEvent := *oldAlertDedupEvent
// 	newErrorDedupEvent := *newAlertDedupEvent
// 	oldErrorDedupEvent.Type = "RULE_ERROR"
// 	newErrorDedupEvent.Type = "RULE_ERROR"
// 	assert.NoError(t, handler.Do(&oldErrorDedupEvent, &newErrorDedupEvent))

// 	ddbMock.AssertExpectations(t)
// 	sqsMock.AssertExpectations(t)
// 	mockRoundTripper.AssertExpectations(t)
// 	metricsMock.AssertExpectations(t)
// }

func generateResponse(body interface{}, httpCode int) *http.Response {
	serializedBody, _ := jsoniter.MarshalToString(body)
	return &http.Response{StatusCode: httpCode, Body: ioutil.NopCloser(strings.NewReader(serializedBody))}
}

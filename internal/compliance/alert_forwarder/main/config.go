package main

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"net/http"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	policiesclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var (
	env        envConfig
	awsSession *session.Session
	ddbClient  dynamodbiface.DynamoDBAPI
	sqsClient  sqsiface.SQSAPI

	httpClient   *http.Client
	policyClient *policiesclient.PantherAnalysisAPI
	policyConfig *policiesclient.TransportConfig
)

type envConfig struct {
	AlertsTable      string `required:"true" split_words:"true"`
	AlertingQueueURL string `required:"true" split_words:"true"`
	AnalysisAPIHost  string `required:"true" split_words:"true"`
	AnalysisAPIPath  string `required:"true" split_words:"true"`
}

// Setup parses the environment and builds the AWS and http clients.
func Setup() {
	envconfig.MustProcess("", &env)

	awsSession = session.Must(session.NewSession())
	ddbClient = dynamodb.New(awsSession)
	sqsClient = sqs.New(awsSession)
	httpClient = gatewayapi.GatewayClient(awsSession)
	policyConfig = policiesclient.DefaultTransportConfig().
		WithHost(env.AnalysisAPIHost).
		WithBasePath(env.AnalysisAPIPath)
	policyClient = policiesclient.NewHTTPClientWithConfig(nil, policyConfig)
}

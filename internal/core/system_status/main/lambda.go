package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/panther-labs/panther/api/lambda/system_status/models"
	"github.com/panther-labs/panther/internal/core/system_status/api"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

var router *genericapi.Router

func lambdaHandler(ctx context.Context, request *models.LambdaInput) (interface{}, error) {
	lambdalogger.ConfigureGlobal(ctx, nil)
	return router.HandleWithContext(ctx, request)
}

func main() {
	router = genericapi.NewRouter("core", "system_status", nil, api.NewAPI())
	lambda.Start(lambdaHandler)
}

package models

// LambdaInput is the collection of all possible args to the Lambda function.
type LambdaInput struct {
	GetSystemStatus *GetSystemStatusInput `json:"getSystemStatus"`
}

// GetSystemStatusInput
type GetSystemStatusInput struct {
	ID string `json:"id" validate:"required"`
}

// GetSystemStatusOutput
type GetSystemStatusOutput struct {
	Status string `json:"status"`
	Message string `json:"message"`
}

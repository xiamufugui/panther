package system

type Status string

const(
	Ok = "Ok"
	AuthErr Status = "AuthErr"
	Err Status = "Err"
)

type Subsystem string

const(
	Sources Subsystem = "Sources"
	Destination Subsystem = "Destinations"
	Classification Subsystem = "Classification"
	Datalake Subsystem = "Datalake"
)

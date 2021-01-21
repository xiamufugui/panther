package system

// The Status reported by Operations performed by different subsystems
type Status string



// Panther's subsystem
type Subsystem string
const(
	Sources Subsystem = "Sources"
	Destinations Subsystem = "Destinations"
	LogProcessing Subsystem = "LogProcessing"
	Detections Subsystem = "Detections"
	Datalake Subsystem = "Datalake"
)

// The different operations performed by Panther's different subsystems
type Operation string
const(
	// Sources operations
	AssumeRole Operation = "AssumeRole"
	GetObject Operation = "GetObject"
	PullData Operation = "PullData"

	// Log Processing operation
	ClassifyEvent Operation = "ClassifyEvent"

	// Data Lake operation
	StoreData Operation = "StoreData"

	// Destinations operation
	SendAlert Operation = "SendAlert"

	// Detections operation
	ProcessRule Operation = "ProcessRule"
	ProcessPolicy Operation = "ProcessPolicy"
)

package panthermetrics

const(

	// Subsystem dimensions
	SubSystem = "Subsystem"
	SubsystemSources = "Sources"
	SubsystemDestinations = "Destinations"
	SubsystemLogProcessing = "LogProcessing"
	SubsystemDetections = "Detections"
	SubsystemDatalake = "Datalake"

	// Status dimensions
	Status = "Status"
	// Status indicating that a subsystem operation is well
	StatusOk = "Ok"
	// Status indicating that a subsystem is experiencing authZ/N errors
	StatusAuthErr = "AuthErr"
	// Status indicating some general error with the subsystem
	StatusErr = "Err"

	// ID dimensions
	ID = "ID"
)

var (
	// Sources metrics
	AssumeRoleOp *Counter
	GetObjectOp *Counter
	PullDataOp *Counter
)

func Setup() {
	AssumeRoleOp = metricsManager.NewCounter("AssumeRole").
		With(SubSystem, SubsystemLogProcessing)
	GetObjectOp = metricsManager.NewCounter("GetObject").
		With(SubSystem, SubsystemLogProcessing)
	PullDataOp = metricsManager.NewCounter("PullData").
		With(SubSystem, SubsystemLogProcessing)
}

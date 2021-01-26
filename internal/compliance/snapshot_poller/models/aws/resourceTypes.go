package aws

// Exported set of ResourceTypes. This export was initially created to provide a hardcoded set of
// valid resource types to the analysis api so we could validate resource types on create/update
//
// NOTE! - This hardcoded data set is found in several places in our code base.
// Until this data is sourced from a single location you need to check if any additions
// or modifications to this data need to coincide with updates in the other places where this data
// is hardcoded.
//
// Locations may not be in this list! right now this data is hardcoded in
// • internal/compliance/snapshot_poller/models/aws/ResourceTypes.go
// • internal/compliance/snapshot_poller/pollers/aws/clients.go
//
// • web/src/constants.ts
//
var ResourceTypes = map[string]struct{}{
  AcmCertificateSchema: struct{}{},
  CloudFormationStackSchema: struct{}{},
  CloudTrailSchema: struct{}{},
  CloudWatchLogGroupSchema: struct{}{},
  ConfigServiceSchema: struct{}{},
  DynamoDBTableSchema: struct{}{},
  Ec2AmiSchema: struct{}{},
  Ec2InstanceSchema: struct{}{},
  Ec2NetworkAclSchema: struct{}{},
  Ec2SecurityGroupSchema: struct{}{},
  Ec2VolumeSchema: struct{}{},
  Ec2VpcSchema: struct{}{},
  EcsClusterSchema: struct{}{},
  EksClusterSchema: struct{}{},
  Elbv2LoadBalancerSchema: struct{}{},
  GuardDutySchema: struct{}{},
  IAMGroupSchema: struct{}{},
  IAMPolicySchema: struct{}{},
  IAMRoleSchema: struct{}{},
  IAMRootUserSchema: struct{}{},
  IAMUserSchema: struct{}{},
  KmsKeySchema: struct{}{},
  LambdaFunctionSchema: struct{}{},
  PasswordPolicySchema: struct{}{},
  RDSInstanceSchema: struct{}{},
  RedshiftClusterSchema: struct{}{},
  S3BucketSchema: struct{}{},
  WafRegionalWebAclSchema: struct{}{},
  WafWebAclSchema: struct{}{},
}

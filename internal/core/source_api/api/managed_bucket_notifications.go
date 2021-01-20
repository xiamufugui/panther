package api

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/pkg/stringset"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"strings"
)

// Creates the necessary resources (topic, subscription to Panther queue) and configures the
// topic notifications for the source's bucket.
// If an error is returned, the resources that have been created before are also returned.
// This function is idempotent.
func ManageBucketNotifications(pantherSess *session.Session, source *models.SourceIntegration) (models.ManagedS3Resources, error) {
	res := models.ManagedS3Resources{}

	stsSess, err := session.NewSession(&aws.Config{
		MaxRetries:  aws.Int(3),
		Credentials: stscreds.NewCredentials(pantherSess, source.RequiredLogProcessingRole()),
	})
	if err != nil {
		return res, errors.Wrap(err, "failed to create sts session")
	}

	bucketRegion, err := getBucketLocation(stsSess, source.S3Bucket)
	if err != nil {
		return res, errors.Wrap(err, "failed to get bucket location")
	}

	// Create the topic with policy and subscribe to Panther input data queue.
	snsClient := sns.New(stsSess, &aws.Config{Region: bucketRegion})

	pantherARN, err := getPantherDeploymentIAM(pantherSess)
	if err != nil {
		return res, errors.Wrap(err, "failed to get Panther deployment IAM info")
	}
	topicARN, err := createTopic(snsClient, pantherARN)
	if err != nil {
		return res, errors.Wrap(err, "failed to create topic")
	}
	res.TopicARN = topicARN
	zap.S().Debugf("created topic %s", *topicARN)

	queueARN := arn.ARN{
		Partition: pantherARN.Partition,
		Service:   "sqs",
		Region:    aws.StringValue(pantherSess.Config.Region),
		AccountID: pantherARN.AccountID,
		Resource:  "panther-input-data-notifications-queue",
	}
	err = subscribeTopicToQueue(snsClient, topicARN, queueARN)
	if err != nil {
		return res, errors.Wrapf(err, "failed to subscribe topic %s to %s", *topicARN, queueARN.String())
	}
	zap.S().Debugf("subscribed topic %s to %s", *topicARN, queueARN.String())

	// Setup bucket notifications
	s3Client := s3.New(stsSess, &aws.Config{Region: bucketRegion})

	managedTopicConfigIDs, err := updateBucketTopicConfigurations(s3Client, source.S3Bucket, source.AWSAccountID, source.ManagedS3Resources.TopicConfigurationIDs, source.S3PrefixLogTypes.S3Prefixes(), topicARN)
	if err != nil {
		return res, errors.WithMessage(err, "failed to replace bucket configuration")
	}
	res.TopicConfigurationIDs = managedTopicConfigIDs
	zap.S().Debugf("replaced bucket topic configurations for %s", source.S3Bucket)

	return res, nil
}

func createTopic(snsClient *sns.SNS, pantherARN arn.ARN) (*string, error) {
	topicPolicy := awsutils.PolicyDocument{
		Version: "2012-10-17",
		Statement: []awsutils.StatementEntry{
			{
				Sid:    "AllowS3EventNotifications",
				Effect: "Allow",
				Action: "sns:Publish",
				Principal: awsutils.Principal{
					Service: "s3.amazonaws.com",
				},
			}, {
				Sid:    "AllowCloudTrailNotification",
				Effect: "Allow",
				Action: "sns:Publish",
				Principal: awsutils.Principal{
					Service: "cloudtrail.amazonaws.com",
				},
			}, {
				Sid:    "AllowSubscriptionToPanther",
				Effect: "Allow",
				Action: "sns:Subscribe",
				Principal: awsutils.Principal{
					AWS: fmt.Sprintf("arn:aws:iam::%s:root", pantherARN.AccountID),
				},
			},
		},
	}
	topicPolicyJSON, err := jsoniter.MarshalToString(topicPolicy)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal topic policy")
	}

	topic, err := snsClient.CreateTopic(&sns.CreateTopicInput{
		Name: aws.String("panther-notifications-topic"),
		Attributes: map[string]*string{
			"Policy": &topicPolicyJSON,
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create topic")
	}

	return topic.TopicArn, nil
}

func subscribeTopicToQueue(snsClient *sns.SNS, topicARN *string, queueARN arn.ARN) error {
	sub := sns.SubscribeInput{
		Endpoint: aws.String(queueARN.String()),
		Protocol: aws.String("sqs"),
		TopicArn: topicARN,
	}
	_, err := snsClient.Subscribe(&sub)
	return err
}

func updateBucketTopicConfigurations(s3Client *s3.S3, bucket, bucketOwner string, existingConfigIDs, prefixes []string, topicARN *string) (newManagedConfigIDs []string, err error) {
	getInput := s3.GetBucketNotificationConfigurationRequest{
		Bucket:              &bucket,
		ExpectedBucketOwner: &bucketOwner,
	}
	config, err := s3Client.GetBucketNotificationConfiguration(&getInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get bucket notifications")
	}

	config.TopicConfigurations, newManagedConfigIDs = updateTopicConfigs(config.TopicConfigurations, existingConfigIDs, prefixes, topicARN)

	putInput := s3.PutBucketNotificationConfigurationInput{
		Bucket:                    &bucket,
		ExpectedBucketOwner:       &bucketOwner,
		NotificationConfiguration: config,
	}
	_, err = s3Client.PutBucketNotificationConfiguration(&putInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to put bucket notifications")
	}
	return newManagedConfigIDs, nil
}

// todo(giorgpsp) unit test
func updateTopicConfigs(topicConfigs []*s3.TopicConfiguration, managedConfigIDs, newPrefixes []string, topicARN *string) ([]*s3.TopicConfiguration, []string) {
	var newConfigs []*s3.TopicConfiguration
	var newManagedConfigIDs []string

	added := make(map[string]struct{})
	for _, c := range topicConfigs {
		if stringset.Contains(managedConfigIDs, *c.Id) {
			// Panther-created. Keep it if its prefix is included in newPrefixes.
			pref := prefixFromFilterRules(c.Filter.Key.FilterRules)
			if pref != nil && stringset.Contains(newPrefixes, *pref) {
				newConfigs = append(newConfigs, c)
				added[*pref] = struct{}{}
				newManagedConfigIDs = append(newManagedConfigIDs, *c.Id)
			}
		} else {
			// User-created, keep it
			newConfigs = append(newConfigs, c)
		}
	}

	for _, p := range newPrefixes {
		if _, ok := added[p]; ok {
			continue
		}
		c := s3.TopicConfiguration{
			Id:     aws.String("panther-managed-" + uuid.New().String()),
			Events: []*string{aws.String("s3:ObjectCreated:*")},
			Filter: &s3.NotificationConfigurationFilter{
				Key: &s3.KeyFilter{
					FilterRules: []*s3.FilterRule{{
						Name:  aws.String("prefix"),
						Value: aws.String(p),
					}},
				},
			},
			TopicArn: topicARN,
		}
		newConfigs = append(newConfigs, &c)
		newManagedConfigIDs = append(newManagedConfigIDs, *c.Id)
	}

	return newConfigs, newManagedConfigIDs
}

func prefixFromFilterRules(rules []*s3.FilterRule) *string {
	for _, fr := range rules {
		if strings.ToLower(aws.StringValue(fr.Name)) == "prefix" {
			return fr.Value
		}
	}
	return nil
}

func getBucketLocation(stsSess *session.Session, bucket string) (*string, error) {
	s3Client := s3.New(stsSess)
	bucketLoc, err := s3Client.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: &bucket})
	if err != nil {
		return nil, err
	}
	if bucketLoc.LocationConstraint == nil {
		return aws.String(endpoints.UsEast1RegionID), nil
	}
	return bucketLoc.LocationConstraint, nil
}

func getPantherDeploymentIAM(sess *session.Session) (arn.ARN, error) {
	output, err := sts.New(sess).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return arn.ARN{}, errors.Wrap(err, "failed to get Panther AWS identity ")
	}
	pantherARN, err := arn.Parse(aws.StringValue(output.Arn))
	if err != nil {
		return arn.ARN{}, errors.Wrap(err, "failed to parse Panther ARN")
	}
	return pantherARN, nil
}

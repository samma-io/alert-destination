package awsadapt

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// Options say what to build. The endpoint overrides are for localstack and
// tests; in the account they are empty and the SDK resolves the real endpoints.
type Options struct {
	LedgerTable string

	// ArchiveBucket and QueueURL are optional; Clients.Archive and
	// Clients.Queue are nil when they are empty.
	ArchiveBucket string
	QueueURL      string

	DynamoDBEndpointURL string
	SSMEndpointURL      string
	S3EndpointURL       string
	SQSEndpointURL      string
}

// Clients is everything this service needs from AWS, already narrowed to the
// interfaces the rest of the codebase declares.
//
// Construction lives here rather than in main so that main never names an SDK
// type either. That is what keeps TestPackages_DoNotImportTheAWSSDK a statement
// about the whole repository rather than about most of it.
type Clients struct {
	Ledger     *LedgerStore
	Parameters *ParameterStore

	// Archive is nil unless Options.ArchiveBucket is set.
	Archive *ObjectStore
	// Queue is nil unless Options.QueueURL is set.
	Queue *Queue
}

// New builds the AWS-backed implementations.
func New(ctx context.Context, opts Options) (*Clients, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS configuration: %w", err)
	}

	dynamo := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		if opts.DynamoDBEndpointURL != "" {
			o.BaseEndpoint = &opts.DynamoDBEndpointURL
		}
	})
	parameters := ssm.NewFromConfig(cfg, func(o *ssm.Options) {
		if opts.SSMEndpointURL != "" {
			o.BaseEndpoint = &opts.SSMEndpointURL
		}
	})

	clients := &Clients{
		Ledger:     &LedgerStore{API: dynamo, Table: opts.LedgerTable},
		Parameters: &ParameterStore{API: parameters},
	}

	if opts.ArchiveBucket != "" {
		objects := s3.NewFromConfig(cfg, func(o *s3.Options) {
			if opts.S3EndpointURL != "" {
				o.BaseEndpoint = &opts.S3EndpointURL
				// Emulators serve buckets by path, not by virtual host.
				o.UsePathStyle = true
			}
		})
		clients.Archive = &ObjectStore{API: objects, Bucket: opts.ArchiveBucket}
	}

	if opts.QueueURL != "" {
		queue := sqs.NewFromConfig(cfg, func(o *sqs.Options) {
			if opts.SQSEndpointURL != "" {
				o.BaseEndpoint = &opts.SQSEndpointURL
			}
		})
		clients.Queue = &Queue{API: queue, URL: opts.QueueURL}
	}

	return clients, nil
}

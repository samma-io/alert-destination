package awsadapt

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// Options are the endpoint overrides. Both are for localstack and tests; in the
// account they are empty and the SDK resolves the real endpoints.
type Options struct {
	LedgerTable         string
	DynamoDBEndpointURL string
	SSMEndpointURL      string
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

	return &Clients{
		Ledger:     &LedgerStore{API: dynamo, Table: opts.LedgerTable},
		Parameters: &ParameterStore{API: parameters},
	}, nil
}

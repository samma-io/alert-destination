package awsadapt

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/samma-io/alert-destination/internal/secrets"
)

// MaxParametersPerCall is SSM's limit on GetParameters.
const MaxParametersPerCall = 10

// SSMAPI is the slice of SSM this package uses.
type SSMAPI interface {
	GetParameters(context.Context, *ssm.GetParametersInput, ...func(*ssm.Options)) (*ssm.GetParametersOutput, error)
}

// ParameterStore implements secrets.Getter over SSM Parameter Store.
type ParameterStore struct {
	API SSMAPI
}

// Get reads several parameters, batching within the API's limit.
//
// GetParameters rather than GetParameter per name: SSM's throughput quota is
// account-wide, and a burst of cold starts each making one call per secret is
// how a service throttles itself and everything else in the account.
//
// Note that reading a SecureString needs kms:Decrypt on the key as well as
// ssm:GetParameters. Without the KMS grant the call fails in a way that looks
// exactly like a bad token downstream, which is why it is called out here and in
// the Terraform.
func (p *ParameterStore) Get(ctx context.Context, names ...string) (map[string]string, error) {
	out := make(map[string]string, len(names))

	for start := 0; start < len(names); start += MaxParametersPerCall {
		end := min(start+MaxParametersPerCall, len(names))
		batch := names[start:end]

		resp, err := p.API.GetParameters(ctx, &ssm.GetParametersInput{
			Names:          batch,
			WithDecryption: aws.Bool(true),
		})
		if err != nil {
			return nil, fmt.Errorf("reading %d parameters from SSM: %w", len(batch), err)
		}

		// InvalidParameters lists names SSM does not have, and it is not an
		// error. Leaving them out of the result is what lets the caller say
		// "the secret has not been set" rather than passing an empty string to
		// a destination and reporting a bad token.
		for _, param := range resp.Parameters {
			out[aws.ToString(param.Name)] = aws.ToString(param.Value)
		}
	}
	return out, nil
}

var _ secrets.Getter = (*ParameterStore)(nil)

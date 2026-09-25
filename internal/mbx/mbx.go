package mbx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/sethvargo/go-githubactions"
)

// keyPrefix keeps mbx objects under the stack's cache/ prefix, which the
// runner role may read and write and the cache lifecycle rule expires.
const keyPrefix = "cache/mbx"

// shortCredentialLifetime is how little validity left on the exported
// credentials earns a warning: mbx cannot refresh them, so a job that outlives
// them loses the remote cache for the rest of the job.
const shortCredentialLifetime = time.Hour

// credentialTimeout bounds the instance metadata request.
const credentialTimeout = 10 * time.Second

var (
	repositoryID   = regexp.MustCompile(`^[0-9]+$`)
	repositoryName = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
)

// retrieveCredentials resolves the RunsOn instance profile through IMDS, never
// through credentials another workflow step may have placed in the
// environment. Tests replace it.
var retrieveCredentials = func(ctx context.Context) (aws.Credentials, error) {
	return instanceRoleCredentials(ctx, imds.New(imds.Options{}))
}

// instanceRoleCredentials reads the instance role's temporary credentials from
// IMDS directly, rather than through the SDK's ec2rolecreds provider. That
// provider caps Expires at an hour from now so the SDK refreshes early, which is
// right for a refreshing client but misstates the lifetime of the snapshot this
// action exports, and that lifetime is what decides how long mbx keeps working.
func instanceRoleCredentials(ctx context.Context, client *imds.Client) (aws.Credentials, error) {
	roles, err := metadata(ctx, client, "iam/security-credentials/")
	if err != nil {
		return aws.Credentials{}, err
	}
	role := strings.TrimSpace(strings.SplitN(strings.TrimSpace(roles), "\n", 2)[0])
	if role == "" {
		return aws.Credentials{}, fmt.Errorf("no instance role is attached to this runner")
	}
	document, err := metadata(ctx, client, "iam/security-credentials/"+role)
	if err != nil {
		return aws.Credentials{}, err
	}
	var response struct {
		Code            string
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string
		Token           string
		Expiration      time.Time
	}
	if err := json.Unmarshal([]byte(document), &response); err != nil {
		return aws.Credentials{}, fmt.Errorf("decode the instance role credentials: %w", err)
	}
	if response.Code != "" && response.Code != "Success" {
		return aws.Credentials{}, fmt.Errorf("the instance role credentials are unavailable: %s", response.Code)
	}
	return aws.Credentials{
		AccessKeyID:     response.AccessKeyID,
		SecretAccessKey: response.SecretAccessKey,
		SessionToken:    response.Token,
		Source:          "EC2InstanceMetadata",
		CanExpire:       !response.Expiration.IsZero(),
		Expires:         response.Expiration,
	}, nil
}

func metadata(ctx context.Context, client *imds.Client, path string) (string, error) {
	output, err := client.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
	if err != nil {
		return "", fmt.Errorf("read %s from instance metadata: %w", path, err)
	}
	defer output.Content.Close()
	body, err := io.ReadAll(output.Content)
	if err != nil {
		return "", fmt.Errorf("read %s from instance metadata: %w", path, err)
	}
	return string(body), nil
}

// ConfigureMbx configures mbx (Mr. Boxington) to use the RunsOn S3 cache bucket
// as its remote cache. Currently only supports the "s3" backend.
//
// Nothing is exported unless every value resolves, so a job never runs with a
// remote URL that has no credentials behind it.
func ConfigureMbx(action *githubactions.Action, backend string) error {
	if backend != "s3" {
		action.Warningf("Unsupported mbx backend: %s. Only 's3' is currently supported.", backend)
		return nil
	}

	bucket := os.Getenv("RUNS_ON_S3_BUCKET_CACHE")
	if bucket == "" {
		return fmt.Errorf("RUNS_ON_S3_BUCKET_CACHE environment variable is not set; the mbx S3 backend requires it")
	}
	region := os.Getenv("RUNS_ON_AWS_REGION")
	if region == "" {
		return fmt.Errorf("RUNS_ON_AWS_REGION environment variable is not set; the mbx S3 backend requires it")
	}
	namespace, err := Namespace()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), credentialTimeout)
	defer cancel()
	creds, err := retrieveCredentials(ctx)
	if err != nil {
		return fmt.Errorf("resolve the RunsOn instance role credentials: %w", err)
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		return fmt.Errorf("the RunsOn instance role returned incomplete temporary credentials")
	}

	settings := []struct{ key, value string }{
		{"MBX_REMOTE_URL", fmt.Sprintf("s3://%s/%s", bucket, keyPrefix)},
		{"MBX_REMOTE_NAMESPACE", namespace},
		{"MBX_REMOTE_S3_REGION", region},
		// mbx still reduces this to read-only for pull requests, unprotected
		// branches, tags, and releases; only protected-branch pushes publish.
		{"MBX_REMOTE_MODE", "read-write"},
	}

	action.Infof("Configuring mbx with S3 backend...")
	for _, setting := range settings {
		action.SetEnv(setting.key, setting.value)
		action.Infof("Set %s=%s", setting.key, setting.value)
	}

	// mbx reads credentials only from these variables, not from the instance
	// profile, so the role's temporary credentials have to be exported.
	for _, secret := range []string{creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken} {
		action.AddMask(secret)
	}
	action.SetEnv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	action.SetEnv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	action.SetEnv("AWS_SESSION_TOKEN", creds.SessionToken)
	action.Infof("Exported the RunsOn instance role's temporary credentials as AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN.")
	action.Infof("Later steps' AWS tools also use these instead of the instance profile.")

	if creds.CanExpire {
		action.Infof("The exported credentials expire at %s.", creds.Expires.UTC().Format(time.RFC3339))
		if remaining := time.Until(creds.Expires); remaining < shortCredentialLifetime {
			action.Warningf(
				"The exported credentials expire in %s. mbx cannot refresh them, so a job running longer loses the remote cache after that.",
				remaining.Round(time.Minute),
			)
		}
	}

	action.Infof("mbx S3 backend configured successfully!")
	return nil
}

// Namespace returns the mbx remote namespace for this repository: its stable
// numeric ID, which survives renames and is never reused, or the repository's
// owner/name when the ID is unavailable.
func Namespace() (string, error) {
	if id := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY_ID")); id != "" {
		if !repositoryID.MatchString(id) {
			return "", fmt.Errorf("GITHUB_REPOSITORY_ID %q is not a numeric repository ID", id)
		}
		return id, nil
	}
	name := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
	if repositoryName.MatchString(name) && !strings.Contains("/"+name+"/", "/./") && !strings.Contains("/"+name+"/", "/../") {
		return name, nil
	}
	return "", fmt.Errorf("neither GITHUB_REPOSITORY_ID nor a valid GITHUB_REPOSITORY is set; the mbx namespace is derived from them")
}

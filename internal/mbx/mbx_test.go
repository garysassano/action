package mbx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/sethvargo/go-githubactions"
)

func TestNamespacePrefersRepositoryID(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY_ID", "123456789")
	t.Setenv("GITHUB_REPOSITORY", "acme/project")

	namespace, err := Namespace()
	if err != nil {
		t.Fatal(err)
	}
	if namespace != "123456789" {
		t.Fatalf("Namespace() = %q, want the repository ID", namespace)
	}
}

func TestNamespaceFallsBackToRepositoryName(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY_ID", "")
	t.Setenv("GITHUB_REPOSITORY", "acme/my-project.rs")

	namespace, err := Namespace()
	if err != nil {
		t.Fatal(err)
	}
	if namespace != "acme/my-project.rs" {
		t.Fatalf("Namespace() = %q, want the repository name", namespace)
	}
}

func TestNamespaceRejectsValuesMbxCannotUse(t *testing.T) {
	for name, env := range map[string][2]string{
		"missing":          {"", ""},
		"non-numeric id":   {"12a", "acme/project"},
		"relative segment": {"", "acme/.."},
		"extra segment":    {"", "acme/project/extra"},
		"unsafe character": {"", "acme/pro ject"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("GITHUB_REPOSITORY_ID", env[0])
			t.Setenv("GITHUB_REPOSITORY", env[1])
			if namespace, err := Namespace(); err == nil {
				t.Fatalf("Namespace() = %q, want an error", namespace)
			}
		})
	}
}

// configure runs ConfigureMbx against stubbed credentials and returns what it
// wrote to GITHUB_ENV and to the log.
func configure(t *testing.T, backend string, creds aws.Credentials, credsErr error) (string, string, error) {
	t.Helper()
	envFile := filepath.Join(t.TempDir(), "github-env")
	t.Setenv("GITHUB_ENV", envFile)
	t.Setenv("RUNS_ON_S3_BUCKET_CACHE", "runs-on-cache")
	t.Setenv("RUNS_ON_AWS_REGION", "eu-west-1")
	t.Setenv("GITHUB_REPOSITORY_ID", "123456789")

	original := retrieveCredentials
	retrieveCredentials = func(context.Context) (aws.Credentials, error) { return creds, credsErr }
	t.Cleanup(func() { retrieveCredentials = original })

	var log bytes.Buffer
	err := ConfigureMbx(githubactions.New(githubactions.WithWriter(&log)), backend)
	data, readErr := os.ReadFile(envFile)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		t.Fatal(readErr)
	}
	return string(data), log.String(), err
}

func validCredentials(expires time.Time) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     "ASIAEXAMPLE",
		SecretAccessKey: "secret-example",
		SessionToken:    "token-example",
		CanExpire:       true,
		Expires:         expires,
	}
}

func TestConfigureExportsRemoteAndCredentials(t *testing.T) {
	env, log, err := configure(t, "s3", validCredentials(time.Now().Add(6*time.Hour)), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"MBX_REMOTE_URL", "s3://runs-on-cache/cache/mbx",
		"MBX_REMOTE_NAMESPACE", "123456789",
		"MBX_REMOTE_S3_REGION", "eu-west-1",
		"MBX_REMOTE_MODE", "read-write",
		"AWS_ACCESS_KEY_ID", "ASIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY", "secret-example",
		"AWS_SESSION_TOKEN", "token-example",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("GITHUB_ENV is missing %q:\n%s", want, env)
		}
	}
	for _, secret := range []string{"ASIAEXAMPLE", "secret-example", "token-example"} {
		if !strings.Contains(log, "::add-mask::"+secret) {
			t.Errorf("%q was not masked", secret)
		}
	}
	if strings.Contains(log, "::warning") {
		t.Errorf("credentials valid for six hours produced a warning:\n%s", log)
	}
}

func TestConfigureWarnsAboutShortLivedCredentials(t *testing.T) {
	_, log, err := configure(t, "s3", validCredentials(time.Now().Add(20*time.Minute)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log, "::warning") || !strings.Contains(log, "cannot refresh") {
		t.Fatalf("credentials expiring in 20 minutes produced no warning:\n%s", log)
	}
}

func TestConfigureExportsNothingWithoutCredentials(t *testing.T) {
	for name, tc := range map[string]struct {
		creds aws.Credentials
		err   error
	}{
		"metadata error":   {err: errors.New("no instance profile")},
		"no session token": {creds: aws.Credentials{AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: "secret-example"}},
	} {
		t.Run(name, func(t *testing.T) {
			env, _, err := configure(t, "s3", tc.creds, tc.err)
			if err == nil {
				t.Fatal("ConfigureMbx succeeded without usable credentials")
			}
			if env != "" {
				t.Fatalf("a failed configuration exported variables:\n%s", env)
			}
		})
	}
}

func TestConfigureIgnoresUnsupportedBackends(t *testing.T) {
	env, log, err := configure(t, "gha", validCredentials(time.Now().Add(6*time.Hour)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if env != "" {
		t.Fatalf("an unsupported backend exported variables:\n%s", env)
	}
	if !strings.Contains(log, "Unsupported mbx backend") {
		t.Fatalf("an unsupported backend was not reported:\n%s", log)
	}
}

// fakeIMDS serves the two metadata documents an instance role's credentials
// come from, answering the credentials request with document.
func fakeIMDS(t *testing.T, document string) *imds.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
			fmt.Fprint(w, "token")
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			fmt.Fprint(w, "runs-on-role\n")
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/runs-on-role":
			fmt.Fprint(w, document)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return imds.New(imds.Options{Endpoint: server.URL})
}

func TestInstanceRoleCredentialsKeepTheRealExpiry(t *testing.T) {
	expires := time.Now().Add(6 * time.Hour).UTC().Truncate(time.Second)
	client := fakeIMDS(t, fmt.Sprintf(
		`{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret-example","Token":"token-example","Expiration":%q}`,
		expires.Format(time.RFC3339),
	))

	creds, err := instanceRoleCredentials(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "ASIAEXAMPLE" || creds.SecretAccessKey != "secret-example" || creds.SessionToken != "token-example" {
		t.Fatalf("credentials = %+v", creds)
	}
	// The SDK's ec2rolecreds provider would cap this at an hour from now.
	if !creds.CanExpire || !creds.Expires.Equal(expires) {
		t.Fatalf("Expires = %s, want the instance role's %s", creds.Expires, expires)
	}
}

func TestInstanceRoleCredentialsRejectAFailedLookup(t *testing.T) {
	client := fakeIMDS(t, `{"Code":"AssumeRoleUnauthorizedAccess"}`)
	if _, err := instanceRoleCredentials(context.Background(), client); err == nil {
		t.Fatal("a failed credentials document was accepted")
	}
}

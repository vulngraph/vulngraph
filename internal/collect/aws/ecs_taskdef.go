package aws

import (
	"slices"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// Task-definition posture for the ECS checks (AWS FSBP ECS.3/4/5/8/9/18/20/
// 21). DescribeTaskDefinition is already fetched per service for the task
// role and container list, so these fields cost no extra API call. Every key
// is written whenever the task definition was read: an unset field there is
// the AWS default (not privileged, writable root, no user override), which is
// an observation, not missing data.

// awsCredentialEnvNames are the variables FSBP ECS.8 fails outright: their
// presence in plaintext environment is a static credential in the task
// definition, readable by anyone with ecs:DescribeTaskDefinition.
var awsCredentialEnvNames = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"}

// secretEnvNameParts mark a variable name that suggests a secret value.
var secretEnvNameParts = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "credential"}

// referenceEnvNameSuffixes mark a variable that names or locates a secret
// rather than holding one (DB_PASSWORD_ARN, TOKEN_FILE).
var referenceEnvNameSuffixes = []string{"_arn", "_name", "_id", "_path", "_file", "_url", "_region", "_key_id"}

// plaintextSecretEnv returns the names of environment variables that hold a
// credential in plaintext: the FSBP-listed AWS credential names always, and
// other secret-looking names whose value is a real literal (not a
// placeholder, not an ARN reference). Only names are returned — the values
// never leave this function.
func plaintextSecretEnv(env []ecstypes.KeyValuePair) []string {
	var out []string
	for _, kv := range env {
		name, value := awssdk.ToString(kv.Name), awssdk.ToString(kv.Value)
		if name == "" {
			continue
		}
		if slices.Contains(awsCredentialEnvNames, strings.ToUpper(name)) && value != "" {
			out = append(out, name)
			continue
		}
		if secretEnvName(name) && len(value) > 8 && !envValueIsReference(value) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func secretEnvName(name string) bool {
	lower := strings.ToLower(name)
	for _, suf := range referenceEnvNameSuffixes {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}
	for _, part := range secretEnvNameParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

// envValueIsReference reports a value that points at a secret rather than
// being one: an ARN, a template placeholder, a file path, or a URL. A URL
// carrying credentials in its userinfo (https://user:pass@host) is NOT a
// reference — the password is right there.
func envValueIsReference(v string) bool {
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		host, _, _ := strings.Cut(strings.SplitN(v, "://", 2)[1], "/")
		return !strings.Contains(host, "@")
	}
	return strings.HasPrefix(v, "arn:") || strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$(") ||
		strings.HasPrefix(v, "{{") || strings.HasPrefix(v, "/") || v == "CHANGEME" || v == "REPLACE_ME"
}

// containerPostureMeta is one container definition's posture keys.
func containerPostureMeta(cd ecstypes.ContainerDefinition) map[string]string {
	logDriver := ""
	if cd.LogConfiguration != nil {
		logDriver = string(cd.LogConfiguration.LogDriver)
	}
	return map[string]string{
		"privileged":           strconv.FormatBool(awssdk.ToBool(cd.Privileged)),
		"readonly_root_fs":     strconv.FormatBool(awssdk.ToBool(cd.ReadonlyRootFilesystem)),
		"user":                 awssdk.ToString(cd.User),
		"log_driver":           logDriver,
		"plaintext_secret_env": strings.Join(plaintextSecretEnv(cd.Environment), ","),
	}
}

// taskPostureMeta is the task-level posture shared by every container.
func taskPostureMeta(td *ecstypes.TaskDefinition) map[string]string {
	var noTLS []string
	for _, v := range td.Volumes {
		if efs := v.EfsVolumeConfiguration; efs != nil && efs.TransitEncryption != ecstypes.EFSTransitEncryptionEnabled {
			noTLS = append(noTLS, awssdk.ToString(v.Name))
		}
	}
	meta := map[string]string{
		"pid_mode":              string(td.PidMode),
		"efs_volumes_plaintext": strings.Join(noTLS, ","),
	}
	// RuntimePlatform is optional; without it the family is unknown (EC2
	// Windows tasks need not declare it), so the key is omitted.
	if td.RuntimePlatform != nil && td.RuntimePlatform.OperatingSystemFamily != "" {
		meta["os_family"] = string(td.RuntimePlatform.OperatingSystemFamily)
	}
	return meta
}

// taskDefinitionContainersMeta folds every container definition's posture
// onto the task-definition asset as comma-separated container names (and,
// for plaintext secrets, variable names), so a task definition no service
// runs is graded on the same conditions as a service's containers. Every key
// is written: an empty list is the observed "no container does this".
func taskDefinitionContainersMeta(defs []ecstypes.ContainerDefinition) map[string]string {
	var privileged, writable, noLog, rootUser, noUser, secretEnv []string
	for _, cd := range defs {
		name := awssdk.ToString(cd.Name)
		if name == "" {
			continue
		}
		if awssdk.ToBool(cd.Privileged) {
			privileged = append(privileged, name)
		}
		if !awssdk.ToBool(cd.ReadonlyRootFilesystem) {
			writable = append(writable, name)
		}
		if cd.LogConfiguration == nil || cd.LogConfiguration.LogDriver == "" {
			noLog = append(noLog, name)
		}
		switch user := awssdk.ToString(cd.User); {
		case user == "":
			noUser = append(noUser, name)
		case ecsAdminUser(user):
			rootUser = append(rootUser, name)
		}
		secretEnv = append(secretEnv, plaintextSecretEnv(cd.Environment)...)
	}
	slices.Sort(secretEnv)
	return map[string]string{
		"privileged_containers":       strings.Join(privileged, ","),
		"writable_root_fs_containers": strings.Join(writable, ","),
		"no_log_containers":           strings.Join(noLog, ","),
		"root_user_containers":        strings.Join(rootUser, ","),
		"unset_user_containers":       strings.Join(noUser, ","),
		"plaintext_secret_env":        strings.Join(slices.Compact(secretEnv), ","),
	}
}

// ecsAdminUser reports an explicit administrative container user: root or
// UID 0 on Linux, ContainerAdministrator on Windows — the same rule the
// container check applies to the per-container `user` key.
func ecsAdminUser(user string) bool {
	u := strings.ToLower(strings.TrimSpace(user))
	name, _, _ := strings.Cut(u, ":")
	return name == "root" || name == "0" || u == "containeradministrator"
}

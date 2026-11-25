package aws

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// Credential-report polling bounds, matching Access Advisor's: AWS reuses a
// report younger than four hours, so the first call usually returns COMPLETE.
const (
	credReportPollAttempts = 6
	credReportPollInterval = 1500 * time.Millisecond
)

// rootDetailAPI is the slice of IAM the root-account detail reads use. Kept
// apart from iamAPI so the principal-crawl fakes need not grow with it.
type rootDetailAPI interface {
	ListVirtualMFADevices(context.Context, *iam.ListVirtualMFADevicesInput, ...func(*iam.Options)) (*iam.ListVirtualMFADevicesOutput, error)
	GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
}

// rootDetails adds what GetAccountSummary cannot say about the root user:
// whether its MFA is a virtual device (root_virtual_mfa), when it last signed
// in or used a key (root_last_used, RFC3339; "" = never), and whether it has
// a password at all (console_access). Each key is written only from a
// successful read, so an unread credential report leaves console_access
// absent: aws-iam-root-no-mfa then still fires on missing MFA, titled with the
// password status unknown, and never treats the root as password-less.
func rootDetails(ctx context.Context, c rootDetailAPI, partition, accountID string, meta map[string]string) {
	if v, ok := rootHasVirtualMFA(ctx, c, partition, accountID); ok {
		meta["root_virtual_mfa"] = strconv.FormatBool(v)
	}
	content, ok := credentialReport(ctx, c)
	if !ok {
		return
	}
	row, ok := rootReportRow(content)
	if !ok {
		return
	}
	if last, ok := rootLastUsedFromRow(row); ok {
		meta["root_last_used"] = last
	}
	if pw, ok := rootPasswordEnabled(row); ok {
		meta["console_access"] = strconv.FormatBool(pw)
	}
}

// rootHasVirtualMFA reports whether an assigned virtual MFA device belongs to
// the root user. AWS names the root's virtual device
// "arn:…:mfa/root-account-mfa-device"; the assigned user ARN is the root ARN.
func rootHasVirtualMFA(ctx context.Context, c rootDetailAPI, partition, accountID string) (bool, bool) {
	rootARN := "arn:" + partition + ":iam::" + accountID + ":root"
	var marker *string
	for {
		out, err := c.ListVirtualMFADevices(ctx, &iam.ListVirtualMFADevicesInput{
			AssignmentStatus: iamtypes.AssignmentStatusTypeAssigned, Marker: marker,
		})
		if err != nil || out == nil {
			return false, false
		}
		for _, d := range out.VirtualMFADevices {
			if strings.HasSuffix(awssdk.ToString(d.SerialNumber), ":mfa/root-account-mfa-device") ||
				(d.User != nil && awssdk.ToString(d.User.Arn) == rootARN) {
				return true, true
			}
		}
		if !out.IsTruncated {
			return false, true
		}
		marker = out.Marker
	}
}

// credentialReport generates (or reuses) and downloads the account's
// credential report CSV.
func credentialReport(ctx context.Context, c rootDetailAPI) ([]byte, bool) {
	for i := 0; i < credReportPollAttempts; i++ {
		gen, err := c.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if err != nil || gen == nil {
			return nil, false
		}
		if gen.State == iamtypes.ReportStateTypeComplete {
			rep, err := c.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
			if err != nil || rep == nil {
				return nil, false
			}
			return rep.Content, true
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(credReportPollInterval):
		}
	}
	return nil, false
}

// rootReportRow returns the credential report's <root_account> row keyed by
// column name.
func rootReportRow(content []byte) (map[string]string, bool) {
	rows, err := csv.NewReader(bytes.NewReader(content)).ReadAll()
	if err != nil || len(rows) < 2 {
		return nil, false
	}
	userCol := slices.Index(rows[0], "user")
	if userCol < 0 {
		return nil, false
	}
	for _, r := range rows[1:] {
		if len(r) != len(rows[0]) || r[userCol] != "<root_account>" {
			continue
		}
		row := make(map[string]string, len(r))
		for i, h := range rows[0] {
			row[h] = r[i]
		}
		return row, true
	}
	return nil, false
}

// rootLastUsedFromRow returns the latest root password or access-key use.
// "N/A" and "no_information" mean no recorded use for that credential.
func rootLastUsedFromRow(row map[string]string) (string, bool) {
	var latest time.Time
	for _, f := range []string{"password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date"} {
		v, ok := row[f]
		if !ok {
			return "", false
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil && t.After(latest) {
			latest = t
		}
	}
	if latest.IsZero() {
		return "", true
	}
	return latest.UTC().Format(time.RFC3339), true
}

// rootPasswordEnabled reads the root row's password_enabled. It is false for
// an account whose root credentials were removed (AWS Organizations
// centralized root access): no password means no console sign-in for MFA to
// protect. Any value but true/false (older reports wrote "not_supported" for
// root) says nothing about the password, so it is not an observation.
func rootPasswordEnabled(row map[string]string) (bool, bool) {
	switch strings.ToLower(row["password_enabled"]) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// rootDetailError is logged by collectIAM when any root detail could not be
// read, so a missing permission is visible rather than silent: without the
// credential report aws-iam-root-no-mfa can only say the root password status
// is unknown, and the identity-hygiene MFA penalty stays unmeasured.
func rootDetailError(meta map[string]string) error {
	var unread []string
	for _, k := range []string{"root_virtual_mfa", "root_last_used", "console_access"} {
		if _, ok := meta[k]; !ok {
			unread = append(unread, k)
		}
	}
	if len(unread) == 0 {
		return nil
	}
	return fmt.Errorf("rootDetails: %s unread (iam:ListVirtualMFADevices or the credential report)", strings.Join(unread, ", "))
}

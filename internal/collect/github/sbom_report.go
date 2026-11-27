package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	sbomAPIVersion       = "2026-03-10"
	sbomMaxPolls         = 6
	sbomMaxAttempts      = 3
	sbomMaxRedirects     = 3
	sbomMaxReportBytes   = 32 << 20
	sbomReportTimeout    = 2 * time.Minute
	sbomMaxGenerateBytes = 64 << 10
)

type sbomDocument struct {
	ID       string `json:"SPDXID"`
	Version  string `json:"spdxVersion"`
	Packages []struct {
		ExternalRefs []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

// HTTP/body-reader errors can echo a signed URL. Keep the cause available for
// errors.Is/As, but do not expose its message to logs.
type sbomReadError struct{ cause error }

func (e *sbomReadError) Error() string { return "SBOM transport or response read failed" }
func (e *sbomReadError) Unwrap() error { return e.cause }

// Use the current asynchronous protocol. API redirects are never followed with
// credentials; temporary downloads use fresh credential-free GETs and retain the
// original safenet transport's dial-time SSRF protection at every hop.
func (c *Collector) fetchSBOMReport(ctx context.Context, baseURL, token, fullName string) (sbomDocument, error) {
	ctx, cancel := context.WithTimeout(ctx, sbomReportTimeout)
	defer cancel()
	if err := checkBaseURL(baseURL); err != nil {
		return sbomDocument{}, fmt.Errorf("SBOM API origin: %w", err)
	}
	parts := strings.Split(fullName, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." {
		return sbomDocument{}, errors.New("SBOM repository identity is invalid")
	}
	prefix := strings.TrimRight(baseURL, "/") + "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/dependency-graph/sbom/"
	client := *c.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	resp, err := c.sbomRequest(ctx, &client, prefix+"generate-report", token)
	if err != nil {
		return sbomDocument{}, err
	}
	if resp.StatusCode != http.StatusCreated {
		_ = resp.Body.Close()
		return sbomDocument{}, sbomStatusError(resp)
	}
	var generated struct {
		URL string `json:"sbom_url"`
	}
	if err := decodeSBOMResponse(resp, &generated, sbomMaxGenerateBytes); err != nil {
		return sbomDocument{}, fmt.Errorf("SBOM generation response: %w", err)
	}
	reportURL, err := validateSBOMReportURL(prefix, generated.URL)
	if err != nil {
		return sbomDocument{}, err
	}
	for poll := range sbomMaxPolls {
		resp, err := c.sbomRequest(ctx, &client, reportURL, token)
		if err != nil {
			return sbomDocument{}, err
		}
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusFound:
			return c.downloadSBOM(ctx, &client, resp.Header.Get("Location"))
		case http.StatusAccepted:
			if poll+1 < sbomMaxPolls {
				if err := c.waitForSBOM(ctx, sbomDelay(resp, poll)); err != nil {
					return sbomDocument{}, err
				}
			}
		default:
			return sbomDocument{}, sbomStatusError(resp)
		}
	}
	return sbomDocument{}, errors.New("SBOM report remains pending after bounded polling")
}

func validateSBOMReportURL(prefix, raw string) (string, error) {
	want, _ := url.Parse(prefix)
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || u.Scheme != want.Scheme || !strings.EqualFold(u.Host, want.Host) {
		return "", errors.New("SBOM report URL is outside the authorized API origin")
	}
	pathPrefix := want.Path + "fetch-report/"
	if len(u.Path) <= len(pathPrefix) || !strings.EqualFold(u.Path[:len(pathPrefix)], pathPrefix) {
		return "", errors.New("SBOM report URL does not belong to the requested repository")
	}
	id := u.Path[len(pathPrefix):]
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != strings.ToLower(id) {
		return "", errors.New("SBOM report identifier is invalid")
	}
	return u.String(), nil
}

func (c *Collector) downloadSBOM(ctx context.Context, client *http.Client, raw string) (sbomDocument, error) {
	for hop := 0; hop <= sbomMaxRedirects; hop++ {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
			return sbomDocument{}, errors.New("SBOM download URL must be absolute HTTPS without user information or fragment")
		}
		resp, err := c.sbomRequest(ctx, client, u.String(), "")
		if err != nil {
			return sbomDocument{}, err
		}
		if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
			_ = resp.Body.Close()
			next, err := url.Parse(resp.Header.Get("Location"))
			if err != nil || next.String() == "" {
				return sbomDocument{}, errors.New("SBOM download redirect is invalid")
			}
			raw = u.ResolveReference(next).String()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return sbomDocument{}, sbomStatusError(resp)
		}
		// Downloads are SPDX documents. Accept the historical API envelope too,
		// but require an identifiable SPDX 2 document, never a malformed empty map.
		var payload struct {
			sbomDocument
			SBOM *sbomDocument `json:"sbom"`
		}
		if err := decodeSBOMResponse(resp, &payload, sbomMaxReportBytes); err != nil {
			return sbomDocument{}, fmt.Errorf("SBOM document: %w", err)
		}
		doc := payload.sbomDocument
		if payload.SBOM != nil {
			if doc.ID != "" || doc.Version != "" {
				return sbomDocument{}, errors.New("SBOM document has ambiguous envelopes")
			}
			doc = *payload.SBOM
		}
		if doc.ID == "" || !strings.HasPrefix(doc.Version, "SPDX-2.") || doc.Packages == nil {
			return sbomDocument{}, errors.New("SBOM download is not a supported SPDX 2 document")
		}
		return doc, nil
	}
	return sbomDocument{}, errors.New("SBOM download exceeded redirect limit")
}

func decodeSBOMResponse(resp *http.Response, out any, limit int64) error {
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return &sbomReadError{cause: err}
	}
	if int64(len(data)) > limit {
		return errors.New("response exceeds SBOM byte limit")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func sbomStatusError(resp *http.Response) error {
	return fmt.Errorf("SBOM response: %w", &apiError{status: resp.StatusCode, rateLimited: resp.StatusCode == http.StatusTooManyRequests || resp.Header.Get("X-RateLimit-Remaining") == "0"})
}

// A cloned client retains the guarded transport, disables all automatic
// redirects, and has no cookie jar. Downloads never receive API credentials or
// influence the installation's API rate bucket. Errors omit temporary URL/query.
func (c *Collector) sbomRequest(ctx context.Context, client *http.Client, target, token string) (*http.Response, error) {
	for attempt := range sbomMaxAttempts {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("SBOM request canceled: %w", err)
		}
		if token != "" {
			if err := getRateState(token).waitIfNeeded(ctx); err != nil {
				return nil, fmt.Errorf("SBOM API rate wait: %w", err)
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, errors.New("SBOM request URL is invalid")
		}
		req.Header.Set("Accept", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", sbomAPIVersion)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, &sbomReadError{cause: err}
		}
		if token != "" {
			getRateState(token).update(resp)
		}
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 || (resp.StatusCode == http.StatusForbidden && (resp.Header.Get("Retry-After") != "" || resp.Header.Get("X-RateLimit-Remaining") == "0"))
		if !retry || attempt+1 == sbomMaxAttempts {
			return resp, nil
		}
		_ = resp.Body.Close()
		if err := c.waitForSBOM(ctx, sbomDelay(resp, attempt)); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("SBOM retry budget exhausted")
}

func sbomDelay(resp *http.Response, attempt int) time.Duration {
	delay := time.Second << min(attempt, 3)
	// GitHub asks for at least a minute on a secondary limit without a
	// Retry-After value. A report deadline may end the job before another try.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
		delay = time.Minute << min(attempt, 3)
	}
	if value := resp.Header.Get("Retry-After"); value != "" {
		if seconds, err := strconv.ParseInt(value, 10, 32); err == nil && seconds > 0 {
			delay = time.Duration(seconds) * time.Second
		} else if at, err := http.ParseTime(value); err == nil && time.Until(at) > 0 {
			delay = time.Until(at)
		}
	}
	if seconds, err := strconv.ParseInt(resp.Header.Get("X-Poll-Interval"), 10, 32); err == nil && seconds > 0 {
		delay = max(delay, time.Duration(seconds)*time.Second)
	}
	return delay
}

func (c *Collector) waitForSBOM(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && delay > time.Until(deadline) {
		return errors.New("SBOM wait exceeds remaining report deadline")
	}
	if c.sbomWait != nil {
		return c.sbomWait(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

package azuredisk

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/pageblob"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

// pageDiffer lists the byte ranges that changed between two incremental
// snapshots of one disk, given the read SAS URL of each.
type pageDiffer interface {
	changedRanges(ctx context.Context, nextURL, baseURL string) ([]diskscan.Extent, error)
}

// blobDiffer asks the blob service for the page-range diff of next against
// base. It sends its requests through the supplied SSRF-guarded client.
type blobDiffer struct{ client *http.Client }

func (d blobDiffer) changedRanges(ctx context.Context, nextURL, baseURL string) ([]diskscan.Extent, error) {
	blob, err := pageblob.NewClientWithNoCredential(nextURL, &pageblob.ClientOptions{
		ClientOptions: azcore.ClientOptions{Transport: d.client},
	})
	if err != nil {
		return nil, errors.New("azuredisk: bad access URL")
	}
	pager := blob.NewGetPageRangesDiffPager(&pageblob.GetPageRangesDiffOptions{PrevSnapshotURL: &baseURL})
	var out []diskscan.Extent
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if re, ok := errors.AsType[*azcore.ResponseError](err); ok && (re.StatusCode == http.StatusBadRequest || re.StatusCode == http.StatusConflict) {
				return nil, fmt.Errorf("azuredisk: page-range diff refused (%s): %w", re.ErrorCode, diskscan.ErrNoDiff)
			}
			return nil, fmt.Errorf("azuredisk: page-range diff: %s", redact(err))
		}
		for _, r := range page.PageRange {
			if r != nil && r.Start != nil && r.End != nil && *r.End >= *r.Start {
				out = append(out, diskscan.Extent{Offset: *r.Start, Length: *r.End - *r.Start + 1})
			}
		}
		for _, r := range page.ClearRange {
			if r != nil && r.Start != nil && r.End != nil && *r.End >= *r.Start {
				out = append(out, diskscan.Extent{Offset: *r.Start, Length: *r.End - *r.Start + 1})
			}
		}
	}
	return out, nil
}

// redact keeps the error class but drops the request URL, which carries the SAS.
func redact(err error) string {
	if re, ok := errors.AsType[*azcore.ResponseError](err); ok {
		return fmt.Sprintf("status %d %s", re.StatusCode, re.ErrorCode)
	}
	return "transport error"
}

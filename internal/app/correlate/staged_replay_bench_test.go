package correlate

import (
	"context"
	"fmt"
	"testing"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Replays the actual private spool and decoder, excluding source construction.
// Allocation/CPU attribution complements real-database end-to-end costs.
func BenchmarkStagedReplay(b *testing.B) {
	s, err := newStagedFile(DefaultStagedViewLimits())
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	for i := range 10000 {
		a := asset.Asset{ID: fmt.Sprintf("compute-%09d", i), Type: "ec2_instance", AccountID: fmt.Sprint(i % 500),
			PublicIP: "203.0.113.1", Name: "compute-name", Metadata: map[string]string{"iam_role_arn": "arn:aws:iam::999999999999:role/shared"},
			Tags: map[string]string{"environment": "prod", "owner": "synthetic"}}
		if err := s.appendInput(s.input, a); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		count := 0
		err := s.Read(context.Background(), []string{"ec2_instance"}, nil, 2048, 2<<20, func(page []asset.Asset) error {
			count += len(page)
			return nil
		})
		if err != nil || count != 10000 {
			b.Fatalf("rows=%d err=%v", count, err)
		}
	}
}

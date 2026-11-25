package snapshotter

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

type fakeWriter struct {
	creates   []ec2.CreateSnapshotInput
	deletes   []string
	dryRunErr error
	createErr error
	deleteErr error
	created   ec2.CreateSnapshotOutput
}

func (f *fakeWriter) CreateSnapshot(_ context.Context, in *ec2.CreateSnapshotInput, _ ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error) {
	f.creates = append(f.creates, *in)
	if aws.ToBool(in.DryRun) {
		return nil, f.dryRunErr
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	return &f.created, nil
}

func (f *fakeWriter) DeleteSnapshot(_ context.Context, in *ec2.DeleteSnapshotInput, _ ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
	f.deletes = append(f.deletes, aws.ToString(in.SnapshotId))
	return &ec2.DeleteSnapshotOutput{}, f.deleteErr
}

type fakeReader struct {
	byRegion map[string][][]ec2types.Snapshot
	err      error
	inputs   []ec2.DescribeSnapshotsInput
	region   string
}

func (f *fakeReader) DescribeSnapshots(_ context.Context, in *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	f.inputs = append(f.inputs, *in)
	if f.err != nil {
		return nil, f.err
	}
	pages := f.byRegion[f.region]
	if len(pages) == 0 {
		return &ec2.DescribeSnapshotsOutput{}, nil
	}
	i := 0
	if in.NextToken != nil {
		i, _ = strconv.Atoi(*in.NextToken)
	}
	out := &ec2.DescribeSnapshotsOutput{Snapshots: pages[i]}
	if i+1 < len(pages) {
		out.NextToken = aws.String(strconv.Itoa(i + 1))
	}
	return out, nil
}

func apiErr(code string) error { return &smithy.GenericAPIError{Code: code, Message: code} }

func optIn(t *testing.T) diskscan.OptIn {
	t.Helper()
	o, err := diskscan.Authorize(diskscan.ConnectorGrant{
		Mode: diskscan.ModeCreateSnapshots, DiskScanRole: "arn:aws:iam::1:role/GraphDiskScan",
		OtherRoles: []string{"arn:aws:iam::1:role/GraphReadOnly"},
	})
	require.NoError(t, err)
	return o
}

func newTagged(t *testing.T, w *fakeWriter, r *fakeReader, regions ...string) *AWS {
	t.Helper()
	a, err := NewAWS(optIn(t), regions, func(region string) (AWSClients, error) {
		r.region = region
		return AWSClients{Write: w, Read: r}, nil
	})
	require.NoError(t, err)
	return a
}

func tagged(id, run string) ec2types.Snapshot {
	return ec2types.Snapshot{
		SnapshotId: aws.String(id), VolumeId: aws.String("vol-1"), VolumeSize: aws.Int32(8),
		Tags: []ec2types.Tag{{Key: aws.String(diskscan.TagKey), Value: aws.String(run)}},
	}
}

func TestNewAWSRefusesInvalidOptIn(t *testing.T) {
	clients := func(string) (AWSClients, error) { return AWSClients{}, nil }

	_, err := NewAWS(diskscan.OptIn{}, nil, clients)
	require.ErrorIs(t, err, diskscan.ErrNotAuthorized)

	for name, grant := range map[string]diskscan.ConnectorGrant{
		"mode off":               {Mode: "off", DiskScanRole: "r"},
		"mode existing":          {Mode: "existing_snapshots", DiskScanRole: "r"},
		"empty role":             {Mode: diskscan.ModeCreateSnapshots},
		"role shared with other": {Mode: diskscan.ModeCreateSnapshots, DiskScanRole: "r", OtherRoles: []string{"r"}},
	} {
		t.Run(name, func(t *testing.T) {
			o, err := diskscan.Authorize(grant)
			require.Error(t, err)
			_, err = NewAWS(o, nil, clients)
			require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
		})
	}

	a, err := NewAWS(optIn(t), nil, clients)
	require.NoError(t, err)
	assert.NotNil(t, a)
}

func TestMethodsRefuseForeignOrZeroOptIn(t *testing.T) {
	w, r := &fakeWriter{dryRunErr: apiErr("DryRunOperation")}, &fakeReader{}
	a := newTagged(t, w, r, "eu-west-1")
	other, err := diskscan.Authorize(diskscan.ConnectorGrant{Mode: diskscan.ModeCreateSnapshots, DiskScanRole: "arn:aws:iam::2:role/Other"})
	require.NoError(t, err)

	for name, o := range map[string]diskscan.OptIn{"zero": {}, "other connector": other} {
		t.Run(name, func(t *testing.T) {
			_, err := a.CreateTagged(context.Background(), o, diskscan.VolumeRef{Region: "eu-west-1", VolumeID: "vol-1"}, "run-1")
			require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
			require.ErrorIs(t, a.DeleteTagged(context.Background(), o, diskscan.Snapshot{ID: "snap-1", Region: "eu-west-1"}), diskscan.ErrNotAuthorized)
			_, err = a.ListTagged(context.Background(), o)
			require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
		})
	}
	assert.Empty(t, w.creates)
	assert.Empty(t, w.deletes)
	assert.Empty(t, r.inputs)
}

func TestCreateTaggedProbesThenCreatesWithTagAtCreation(t *testing.T) {
	start := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	w := &fakeWriter{
		dryRunErr: apiErr("DryRunOperation"),
		created: ec2.CreateSnapshotOutput{
			SnapshotId: aws.String("snap-new"), VolumeSize: aws.Int32(8), Encrypted: aws.Bool(true), StartTime: aws.Time(start),
		},
	}
	a := newTagged(t, w, &fakeReader{}, "eu-west-1")

	snap, err := a.CreateTagged(context.Background(), optIn(t), diskscan.VolumeRef{Region: "eu-west-1", VolumeID: "vol-1"}, "run-1")
	require.NoError(t, err)
	assert.Equal(t, diskscan.Snapshot{
		ID: "snap-new", Provider: "aws", Region: "eu-west-1", VolumeID: "vol-1",
		SizeBytes: 8 << 30, Encrypted: true, Ephemeral: true, CreatedAt: start,
	}, snap)

	require.Len(t, w.creates, 2)
	assert.True(t, aws.ToBool(w.creates[0].DryRun), "the probe comes first")
	assert.Nil(t, w.creates[1].DryRun)
	for _, in := range w.creates {
		require.Len(t, in.TagSpecifications, 1, "the tag is applied at creation, not afterwards")
		spec := in.TagSpecifications[0]
		assert.Equal(t, ec2types.ResourceTypeSnapshot, spec.ResourceType)
		require.Len(t, spec.Tags, 1)
		assert.Equal(t, diskscan.TagKey, aws.ToString(spec.Tags[0].Key))
		assert.Equal(t, "run-1", aws.ToString(spec.Tags[0].Value))
	}
}

func TestCreateTaggedDryRunDenied(t *testing.T) {
	for _, code := range []string{"UnauthorizedOperation", "AccessDenied"} {
		t.Run(code, func(t *testing.T) {
			w := &fakeWriter{dryRunErr: apiErr(code)}
			a := newTagged(t, w, &fakeReader{}, "eu-west-1")
			_, err := a.CreateTagged(context.Background(), optIn(t), diskscan.VolumeRef{Region: "eu-west-1", VolumeID: "vol-1"}, "run-1")
			require.ErrorIs(t, err, ErrPermissionDenied)
			require.Len(t, w.creates, 1, "one probe, no real create, no retry")
			assert.True(t, aws.ToBool(w.creates[0].DryRun))
		})
	}
}

func TestCreateTaggedOtherFailures(t *testing.T) {
	tests := []struct {
		name   string
		w      *fakeWriter
		denied bool
		calls  int
	}{
		{"dry run says nothing", &fakeWriter{}, false, 1},
		{"dry run unexpected error", &fakeWriter{dryRunErr: apiErr("InvalidVolume.NotFound")}, false, 1},
		{"create denied after probe", &fakeWriter{dryRunErr: apiErr("DryRunOperation"), createErr: apiErr("UnauthorizedOperation")}, true, 2},
		{"create fails", &fakeWriter{dryRunErr: apiErr("DryRunOperation"), createErr: errors.New("boom")}, false, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newTagged(t, tc.w, &fakeReader{}, "eu-west-1")
			_, err := a.CreateTagged(context.Background(), optIn(t), diskscan.VolumeRef{Region: "eu-west-1", VolumeID: "vol-1"}, "run-1")
			require.Error(t, err)
			assert.Equal(t, tc.denied, errors.Is(err, ErrPermissionDenied))
			assert.Len(t, tc.w.creates, tc.calls)
		})
	}
}

func TestCreateTaggedReturnsTheRunsExistingSnapshot(t *testing.T) {
	w := &fakeWriter{dryRunErr: apiErr("DryRunOperation")}
	r := &fakeReader{byRegion: map[string][][]ec2types.Snapshot{"eu-west-1": {{tagged("snap-mine", "run-1")}}}}
	a := newTagged(t, w, r, "eu-west-1")

	snap, err := a.CreateTagged(context.Background(), optIn(t), diskscan.VolumeRef{Region: "eu-west-1", VolumeID: "vol-1"}, "run-1")
	require.NoError(t, err)
	assert.Equal(t, "snap-mine", snap.ID)
	assert.True(t, snap.Ephemeral)
	assert.Empty(t, w.creates, "a retry never double-creates")
	require.Len(t, r.inputs, 1)
	var names []string
	for _, f := range r.inputs[0].Filters {
		names = append(names, aws.ToString(f.Name))
	}
	assert.ElementsMatch(t, []string{"tag:" + diskscan.TagKey, "volume-id"}, names)
}

func TestCreateTaggedRejectsEmptyInput(t *testing.T) {
	w := &fakeWriter{dryRunErr: apiErr("DryRunOperation")}
	a := newTagged(t, w, &fakeReader{}, "r")
	_, err := a.CreateTagged(context.Background(), optIn(t), diskscan.VolumeRef{Region: "r", VolumeID: "vol-1"}, "")
	require.Error(t, err)
	_, err = a.CreateTagged(context.Background(), optIn(t), diskscan.VolumeRef{Region: "r"}, "run-1")
	require.Error(t, err)
	assert.Empty(t, w.creates)
}

// Deletion trusts the live tags, never the caller's Snapshot value.
func TestDeleteOnlyTaggedSnapshots(t *testing.T) {
	untagged := ec2types.Snapshot{SnapshotId: aws.String("snap-prod"), VolumeId: aws.String("vol-1")}
	emptyTag := ec2types.Snapshot{
		SnapshotId: aws.String("snap-empty"),
		Tags:       []ec2types.Tag{{Key: aws.String(diskscan.TagKey), Value: aws.String("")}},
	}
	otherTag := ec2types.Snapshot{
		SnapshotId: aws.String("snap-other"),
		Tags:       []ec2types.Tag{{Key: aws.String("backup"), Value: aws.String("daily")}},
	}
	tests := []struct {
		name      string
		live      ec2types.Snapshot
		readErr   error
		deleteErr error
		wantErr   error
		wantDel   bool
	}{
		{name: "tagged is deleted", live: tagged("snap-1", "run-1"), wantDel: true},
		{name: "untagged is refused", live: untagged, wantErr: ErrNotTagged},
		{name: "empty tag value is refused", live: emptyTag, wantErr: ErrNotTagged},
		{name: "different tag is refused", live: otherTag, wantErr: ErrNotTagged},
		{name: "already gone on re-read", readErr: apiErr("InvalidSnapshot.NotFound")},
		{name: "gone between re-read and delete", live: tagged("snap-1", "run-1"), deleteErr: apiErr("InvalidSnapshot.NotFound"), wantDel: true},
		{name: "re-read fails, nothing deleted", readErr: errors.New("throttled"), wantErr: errors.New("throttled")},
		{name: "delete denied", live: tagged("snap-1", "run-1"), deleteErr: apiErr("UnauthorizedOperation"), wantErr: ErrPermissionDenied, wantDel: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{deleteErr: tc.deleteErr}
			r := &fakeReader{err: tc.readErr}
			if tc.readErr == nil {
				r.byRegion = map[string][][]ec2types.Snapshot{"eu-west-1": {{tc.live}}}
			}
			a := newTagged(t, w, r, "eu-west-1")
			// The caller claims the snapshot is ephemeral; only the live tags count.
			err := a.DeleteTagged(context.Background(), optIn(t), diskscan.Snapshot{ID: "snap-1", Region: "eu-west-1", Ephemeral: true})
			switch {
			case tc.wantErr == nil:
				require.NoError(t, err)
			case errors.Is(tc.wantErr, ErrNotTagged), errors.Is(tc.wantErr, ErrPermissionDenied):
				require.ErrorIs(t, err, tc.wantErr)
			default:
				require.ErrorContains(t, err, tc.wantErr.Error())
			}
			if tc.wantDel {
				assert.Equal(t, []string{"snap-1"}, w.deletes)
			} else {
				assert.Empty(t, w.deletes)
			}
			require.NotEmpty(t, r.inputs, "tags are re-read before every delete")
			assert.Equal(t, []string{"snap-1"}, r.inputs[0].SnapshotIds)
		})
	}
}

func TestListTaggedSweepsEveryRegionAndPage(t *testing.T) {
	r := &fakeReader{byRegion: map[string][][]ec2types.Snapshot{
		"eu-west-1": {{tagged("snap-a", "run-1")}, {tagged("snap-b", "run-2")}},
		"us-east-1": {{tagged("snap-c", "run-3")}},
	}}
	a := newTagged(t, &fakeWriter{}, r, "eu-west-1", "us-east-1", "ap-south-1")

	got, err := a.ListTagged(context.Background(), optIn(t))
	require.NoError(t, err)
	var ids []string
	for _, s := range got {
		ids = append(ids, fmt.Sprintf("%s/%s", s.Region, s.ID))
		assert.True(t, s.Ephemeral)
	}
	assert.Equal(t, []string{"eu-west-1/snap-a", "eu-west-1/snap-b", "us-east-1/snap-c"}, ids)
	assert.Equal(t, "tag-key", aws.ToString(r.inputs[0].Filters[0].Name))
	assert.Equal(t, []string{diskscan.TagKey}, r.inputs[0].Filters[0].Values)

	r.err = errors.New("boom")
	_, err = a.ListTagged(context.Background(), optIn(t))
	require.Error(t, err)
}

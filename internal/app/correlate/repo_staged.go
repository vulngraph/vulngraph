package correlate

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

type stagedRef struct {
	offset int64
	size   int64
}
type stagedInputRef struct {
	stagedRef
	charge int64
}

func (r stagedInputRef) logicalBytes() int64 { return r.charge }

type stagedEdgeRef struct {
	ref  stagedRef
	rank int
}
type stagedFile struct {
	input, output *os.File
	groups        map[string]map[string][]stagedInputRef
	edges         []stagedEdgeRef
	annotations   []stagedRef
	edgeIndex     map[string]int
	decodeBuffer  []byte
	encodeBuffer  []byte
	readFile      *os.File
	readOffset    int64
	limits        StagedViewLimits
	stats         StagedViewStats
}

func newStagedFile(limits StagedViewLimits) (*stagedFile, error) {
	if limits.AggregationSpillBytes <= 0 || limits.IndexBytes <= 0 || limits.Rows < 0 || limits.DiskBytes <= 0 || limits.ContextBytes <= 0 || limits.PageBytes <= 0 || limits.PageRows <= 0 || limits.OutputRows < 0 || limits.OutputBytes <= 0 {
		return nil, fmt.Errorf("invalid staged limits: %w", ErrStagedBudget)
	}
	input, err := newAnonymousStagedFile("vulngraph-correlate-input-*")
	if err != nil {
		return nil, fmt.Errorf("create input snapshot: %w", err)
	}
	output, err := newAnonymousStagedFile("vulngraph-correlate-output-*")
	if err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("create output snapshot: %w", err)
	}
	return &stagedFile{input: input, output: output, groups: make(map[string]map[string][]stagedInputRef), edgeIndex: make(map[string]int), limits: limits}, nil
}

// StageView consumes exactly one source query before returning a usable snapshot.
// Type/account indexes point into that immutable file; page/project replay does
// not query ClickHouse again or scan unrelated records in the spool.
func (r *CHRepo) StageView(ctx context.Context, types []string, limits StagedViewLimits) (stagedView, error) {
	snapshot, err := newStagedFile(limits)
	if err != nil {
		return nil, err
	}
	if len(types) == 0 {
		snapshot.stats.SourceComplete = true
		return snapshot, nil
	}
	qctx, cancel := context.WithTimeout(ctx, loadViewTimeout)
	defer cancel()
	qctx = r.ch.WithQuerySettings(qctx, map[string]any{"max_bytes_before_external_group_by": limits.AggregationSpillBytes, "max_block_size": 4096})
	placeholders, typeArgs := dbutil.CHIn(types)
	args := append(append([]any{}, metadataKeyArgs...), typeArgs...)
	buffer := bufio.NewWriterSize(snapshot.input, 256<<10)
	snapshot.stats.SourceQueries = 1
	query := loadStagedForTypesQuery(types)
	err = r.ch.Select(qctx, func(rows driver.Rows) error {
		for rows.Next() {
			a, scanErr := scanCorrelationAsset(rows)
			if scanErr != nil {
				return scanErr
			}
			if err := snapshot.appendInput(buffer, a); err != nil {
				return err
			}
		}
		return rows.Err()
	}, fmt.Sprintf(query, metadataKeyPlaceholders, placeholders), args...)
	if err == nil {
		err = buffer.Flush()
	}
	if err != nil {
		return snapshot, fmt.Errorf("stage correlation source (%d rows, %d bytes): %w", snapshot.stats.SourceRows, snapshot.stats.SpoolBytes, err)
	}
	snapshot.stats.SourceComplete = true
	return snapshot, nil
}

func (s *stagedFile) appendInput(writer io.Writer, a asset.Asset) error {
	data, err := json.Marshal(stagedSourceRow{ID: a.ID, Name: a.Name, Type: a.Type,
		AccountID: a.AccountID, PublicIP: a.PublicIP, PrivateIP: a.PrivateIP, Domain: a.Domain, Tags: a.Tags, Metadata: a.Metadata})
	if err != nil {
		return fmt.Errorf("encode source row: %w", err)
	}
	logicalBytes := int64(len(data))
	s.encodeBuffer = appendStagedSourceFrame(s.encodeBuffer[:0], a)
	size := int64(len(s.encodeBuffer))
	if (s.limits.Rows > 0 && s.stats.SourceRows >= s.limits.Rows) || s.stats.SpoolBytes+size > s.limits.DiskBytes || logicalBytes > s.limits.PageBytes || size > s.limits.PageBytes {
		return fmt.Errorf("source row/disk/row-size ceiling: %w", ErrStagedBudget)
	}
	// Reference slices may retain spare capacity. Group overhead includes the
	// single replay cursor, so replay never allocates a second per-row index.
	charge := int64(48)
	if _, exists := s.groups[a.Type][a.AccountID]; !exists {
		charge += int64(len(a.Type) + len(a.AccountID) + 256)
	}
	if err := s.chargeIndex(charge); err != nil {
		return err
	}
	if _, err := writer.Write(s.encodeBuffer); err != nil {
		return fmt.Errorf("write input snapshot: %w", err)
	}
	if s.groups[a.Type] == nil {
		s.groups[a.Type] = make(map[string][]stagedInputRef)
	}
	s.groups[a.Type][a.AccountID] = append(s.groups[a.Type][a.AccountID], stagedInputRef{stagedRef: stagedRef{offset: s.stats.SpoolBytes, size: size}, charge: logicalBytes})
	s.stats.SourceRows++
	s.stats.SpoolBytes += size
	s.stats.SourceChargeBytes += logicalBytes
	return nil
}

func (s *stagedFile) Count(types []string) int {
	n := 0
	for _, kind := range types {
		for _, refs := range s.groups[kind] {
			n += len(refs)
		}
	}
	return n
}

func (s *stagedFile) Accounts(types []string) []string {
	seen := make(map[string]bool)
	for _, kind := range types {
		for account := range s.groups[kind] {
			seen[account] = true
		}
	}
	accounts := make([]string, 0, len(seen))
	for account := range seen {
		accounts = append(accounts, account)
	}
	sort.Strings(accounts)
	return accounts
}

func (s *stagedFile) Read(ctx context.Context, types []string, account *string, maxRows int, maxBytes int64, consume func([]asset.Asset) error) error {
	if maxRows <= 0 || maxBytes <= 0 {
		return fmt.Errorf("invalid replay page budget: %w", ErrStagedBudget)
	}
	refs := s.refsFor(types, account)
	s.stats.ReplayPasses++
	total := 0
	for _, group := range refs {
		total += len(group.refs)
	}
	pageCapacity := min(maxRows, total, s.limits.PageRows)
	page := make([]asset.Asset, 0, pageCapacity)
	var pageBytes int64
	for len(refs) > 0 {
		ref := refs.pop()
		if err := ctx.Err(); err != nil {
			return err
		}
		if ref.logicalBytes() > maxBytes {
			return fmt.Errorf("single context row: %w", ErrStagedBudget)
		}
		if len(page) > 0 && (len(page) >= maxRows || pageBytes+ref.logicalBytes() > maxBytes) {
			if err := consume(page); err != nil {
				return err
			}
			page, pageBytes = make([]asset.Asset, 0, pageCapacity), 0
		}
		// Decode into the owned page rather than a separately escaping row.
		// A consumer may retain a complete context, so subsequent pages use
		// a new backing array.
		page = append(page, asset.Asset{})
		data, err := s.readFrame(s.input, ref.stagedRef)
		if err != nil {
			return err
		}
		if err := decodeStagedSourceFrame(data, &page[len(page)-1]); err != nil {
			return err
		}
		s.stats.ReplayRows++
		s.stats.ReplayBytes += ref.size
		s.stats.ReplayChargeBytes += ref.logicalBytes()
		pageBytes += ref.logicalBytes()
	}
	if len(page) > 0 {
		return consume(page)
	}
	return nil
}

func (s *stagedFile) readJSON(file *os.File, ref stagedRef, target any) error {
	data, err := s.readFrame(file, ref)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode staged row: %w", err)
	}
	return nil
}

func (s *stagedFile) readFrame(file *os.File, ref stagedRef) ([]byte, error) {
	if ref.offset < 0 || ref.size < 0 || ref.size > s.limits.PageBytes {
		return nil, fmt.Errorf("decode row ceiling: %w", ErrStagedBudget)
	}
	if s.readFile != file || ref.offset < s.readOffset || ref.offset-s.readOffset > int64(len(s.decodeBuffer))-ref.size {
		// Replays merge groups in source order. Amortize adjacent frame reads
		// without loading the whole spool or scanning unrelated scopes.
		size := max(int64(64<<10), ref.size)
		if int64(cap(s.decodeBuffer)) < size {
			s.decodeBuffer = make([]byte, size)
		}
		n, err := file.ReadAt(s.decodeBuffer[:size], ref.offset)
		s.stats.SpoolReadCalls++
		s.stats.SpoolReadBytes += int64(n)
		if (err != nil && !errors.Is(err, io.EOF)) || int64(n) < ref.size {
			return nil, fmt.Errorf("read staged row: %w", errors.Join(err, io.ErrUnexpectedEOF))
		}
		s.decodeBuffer = s.decodeBuffer[:n]
		s.readFile, s.readOffset = file, ref.offset
	}
	offset := ref.offset - s.readOffset
	return s.decodeBuffer[offset : offset+ref.size], nil
}

func (s *stagedFile) appendOutput(value any) (stagedRef, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return stagedRef{}, fmt.Errorf("encode staged output: %w", err)
	}
	size := int64(len(data))
	if size > s.limits.PageBytes || s.stats.OutputBytes+size > s.limits.OutputBytes || s.stats.SpoolBytes+s.stats.OutputBytes+size > s.limits.DiskBytes {
		return stagedRef{}, fmt.Errorf("output byte/disk ceiling: %w", ErrStagedBudget)
	}
	ref := stagedRef{offset: s.stats.OutputBytes, size: size}
	if _, err := s.output.Write(data); err != nil {
		return stagedRef{}, fmt.Errorf("write staged output: %w", err)
	}
	s.stats.OutputBytes += size
	return ref, nil
}

func (s *stagedFile) StageEdges(edges []asset.Edge) error {
	for _, edge := range edges {
		key := edge.SrcID + "|" + edge.EdgeType + "|" + edge.DstID
		rank := confidenceRank[edge.Properties["confidence"]]
		i, exists := s.edgeIndex[key]
		if exists && rank <= s.edges[i].rank {
			// K8s owner exposure can appear on several workload pages. The
			// rule's winner order must span those pages, before global dedupe.
			replace := false
			if rank == s.edges[i].rank && edge.Properties["via"] == "k8s_public_service" {
				var previous asset.Edge
				if err := s.readJSON(s.output, s.edges[i].ref, &previous); err != nil {
					return err
				}
				replace = previous.Properties["via"] == "k8s_public_service" && betterExposure(edge, previous)
			}
			if !replace {
				continue
			}
		}
		if !exists && s.limits.OutputRows > 0 && len(s.edges)+len(s.annotations) >= s.limits.OutputRows {
			return fmt.Errorf("output row ceiling: %w", ErrStagedBudget)
		}
		if !exists {
			if err := s.chargeIndex(int64(len(key) + 96)); err != nil {
				return err
			}
		}
		ref, err := s.appendOutput(edge)
		if err != nil {
			return err
		}
		if exists {
			s.edges[i] = stagedEdgeRef{ref, rank}
		} else {
			s.edgeIndex[key] = len(s.edges)
			s.edges = append(s.edges, stagedEdgeRef{ref, rank})
		}
	}
	s.stats.OutputRows = len(s.edges) + len(s.annotations)
	return nil
}

func (s *stagedFile) StageAnnotations(annotations []asset.Annotation) error {
	for _, annotation := range annotations {
		if s.limits.OutputRows > 0 && len(s.edges)+len(s.annotations) >= s.limits.OutputRows {
			return fmt.Errorf("annotation row ceiling: %w", ErrStagedBudget)
		}
		if err := s.chargeIndex(32); err != nil {
			return err
		}
		ref, err := s.appendOutput(annotation)
		if err != nil {
			return err
		}
		s.annotations = append(s.annotations, ref)
	}
	s.stats.OutputRows = len(s.edges) + len(s.annotations)
	return nil
}

// Publish starts only after every rule succeeded. Storage failure can still
// interrupt ingestion (as in the existing edge path); a visible prefix is
// counted and returned as failure for retry. This is not atomic publication.
func (s *stagedFile) Publish(ctx context.Context, edgeSink func([]asset.Edge) error, annotationSink func([]asset.Annotation) error) (int, error) {
	s.stats.PublicationStarted = true
	for start := 0; start < len(s.edges); {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		var page []asset.Edge
		var bytes int64
		for start < len(s.edges) && len(page) < s.limits.PageRows {
			ref := s.edges[start].ref
			if len(page) > 0 && bytes+ref.size > s.limits.PageBytes {
				break
			}
			var edge asset.Edge
			if err := s.readJSON(s.output, ref, &edge); err != nil {
				return 0, err
			}
			page = append(page, edge)
			bytes += ref.size
			start++
		}
		if err := edgeSink(page); err != nil {
			return 0, fmt.Errorf("publish staged edges: %w", err)
		}
		s.stats.PublishedEdgeRows += len(page)
	}
	for start := 0; start < len(s.annotations); {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		var page []asset.Annotation
		var bytes int64
		for start < len(s.annotations) && len(page) < s.limits.PageRows {
			ref := s.annotations[start]
			if len(page) > 0 && bytes+ref.size > s.limits.PageBytes {
				break
			}
			var annotation asset.Annotation
			if err := s.readJSON(s.output, ref, &annotation); err != nil {
				return 0, err
			}
			page = append(page, annotation)
			bytes += ref.size
			start++
		}
		if err := annotationSink(page); err != nil {
			return 0, fmt.Errorf("publish staged annotations: %w", err)
		}
		s.stats.PublishedAnnotationRows += len(page)
	}
	s.stats.PublicationComplete = true
	return len(s.edges), nil
}

func (s *stagedFile) Stats() StagedViewStats { return s.stats }
func (s *stagedFile) Close() error {
	return errors.Join(s.input.Close(), s.output.Close())
}

// Only the nine projected source columns belong in the replay spool. The
// unused observation timestamps/provider/risk fields otherwise dominate the
// encoding of narrow correlation rows.
type stagedSourceRow struct {
	ID        string
	Name      string `json:",omitempty"`
	Type      string
	AccountID string            `json:",omitempty"`
	PublicIP  string            `json:",omitempty"`
	PrivateIP string            `json:",omitempty"`
	Domain    string            `json:",omitempty"`
	Tags      map[string]string `json:",omitempty"`
	Metadata  map[string]string `json:",omitempty"`
}

// Charge references, copied key bytes and conservative map/group overhead.
// This is an explicit logical index ceiling, not an RSS measurement; Go map
// growth, decoded rule contexts and native memory remain separately measured.
func (s *stagedFile) chargeIndex(bytes int64) error {
	if s.stats.IndexChargeBytes+bytes > s.limits.IndexBytes {
		return fmt.Errorf("snapshot index ceiling: %w", ErrStagedBudget)
	}
	s.stats.IndexChargeBytes += bytes
	return nil
}

// The snapshot is process-local, not a durable ingest generation. Unlink the
// private file immediately: its open handle remains seekable, and the kernel
// releases its space even if this worker is killed before Close runs.
func newAnonymousStagedFile(pattern string) (*os.File, error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(file.Name()); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, err
	}
	return file, nil
}

func (s *stagedFile) CheckContext(types []string, account *string, maxRows int, maxBytes int64) error {
	rows := 0
	var bytes int64
	for _, kind := range types {
		for scope, refs := range s.groups[kind] {
			if account != nil && scope != *account {
				continue
			}
			rows += len(refs)
			if rows >= maxRows {
				return fmt.Errorf("complete context rows: %w", ErrStagedBudget)
			}
			for _, ref := range refs {
				bytes += ref.logicalBytes()
				if bytes > maxBytes {
					return fmt.Errorf("complete context bytes: %w", ErrStagedBudget)
				}
			}
		}
	}
	return nil
}

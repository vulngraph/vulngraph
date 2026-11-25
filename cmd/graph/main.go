// Command graph is the single Vulngraph binary.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/vulngraph/vulngraph/internal/memlimit"
	"github.com/vulngraph/vulngraph/internal/migrate"
	"github.com/vulngraph/vulngraph/pkg/envswitch"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const usage = "usage: graph <serve|worker|scanner|migrate|user|keys|bootstrap|healthcheck|node-posture|scan|demo|version>"

// version is the release this binary was built from, stamped at build time with
// -ldflags "-X main.version=<tag>" (Dockerfile ARG VERSION). Unstamped builds
// report "dev".
var version = "dev"

// Ladybug buffer-pool defaults, mirrored by openGraphDB (worker) and the serve-Ladybug
// block. Declared here because the memory budget must account for the same numbers.
const (
	defaultWorkerLadybugBufferMB = 1280
	defaultServeLadybugBufferMB  = 512
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := loadEnvFile(os.LookupEnv, os.Setenv); err != nil {
		fmt.Fprintln(os.Stderr, "graph:", err)
		os.Exit(1)
	}
	if err := run(ctx, os.Args, os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "graph:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string) error {
	if len(args) < 2 {
		return fmt.Errorf("%s", usage)
	}

	switch args[1] {
	case "serve":
		bufMB, err := serveLadybugBufferMB(getenv)
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		applyMemoryBudget(ctx, getenv, bufMB)
		return serve(ctx, getenv)
	case "worker":
		applyMemoryBudget(ctx, getenv, workerLadybugBufferMB(getenv))
		return worker(ctx, getenv)
	case "scanner":
		applyMemoryBudget(ctx, getenv, 0) // no Ladybug on the scanner pod
		return scanner(ctx, getenv)
	case "migrate":
		return migrate.Run(ctx, pgDSN(getenv), chDSN(getenv))
	case "user":
		return userCmd(ctx, args[2:], getenv)
	case "keys":
		return keysCmd(ctx, args[2:], getenv)
	case "bootstrap":
		return bootstrap(ctx, getenv)
	case "healthcheck":
		return healthcheck(ctx, args[2:], getenv)
	case "node-posture":
		return nodePosture(ctx, args[2:], os.Stdout)
	case "scan":
		return scanCmd(ctx, args[2:], getenv, os.Stdout, os.Stderr)
	case "demo":
		return demoCmd(ctx, args[2:], getenv, os.Stdout)
	case "version":
		return printVersion(os.Stdout)
	default:
		return fmt.Errorf("unknown command %q (%s)", args[1], usage)
	}
}

func printVersion(w io.Writer) error {
	if _, err := fmt.Fprintln(w, version); err != nil {
		return fmt.Errorf("version: %w", err)
	}
	return nil
}

// applyMemoryBudget sizes the Go heap ceiling against the container's real memory
// limit before any real allocation starts, and logs the arithmetic exactly once.
//
// It must run here rather than inside openGraphDB: the budget has to be installed
// even when the graph engine is disabled, and it has to be installed BEFORE the
// collectors and the Ladybug rebuild start allocating, not after. ladybugBufferMB is how
// much of the container is spoken for by the cgo buffer pool, which GOMEMLIMIT
// cannot see — see internal/memlimit.
func applyMemoryBudget(ctx context.Context, getenv func(string) string, ladybugBufferMB int) {
	b := memlimit.Apply(getenv, ladybugBufferMB)
	log.FromContext(ctx).Info().
		Int64("cgroup_mib", b.CgroupLimit/memlimit.MiB).
		Int64("ladybug_buffer_mib", b.LadybugBuffer/memlimit.MiB).
		Int64("reserve_mib", b.Reserve/memlimit.MiB).
		Int64("go_limit_mib", b.GoLimit/memlimit.MiB).
		Bool("applied", b.Applied).
		Int("gogc", b.GCPercent).
		Msg("memory budget: " + b.Reason)
}

// workerLadybugBufferMB and serveLadybugBufferMB resolve the Ladybug buffer-pool size the
// same way the code that opens Ladybug does. Kept beside the budget so the two can
// never read different values — the drift that made the budget unauditable.
func workerLadybugBufferMB(getenv func(string) string) int {
	if getenv("LADYBUG_INTERNAL_PORT") == "" {
		return 0 // graph engine disabled — no cgo pool to account for
	}
	return envInt(getenv, "LADYBUG_BUFFER_MB", defaultWorkerLadybugBufferMB)
}

func serveLadybugBufferMB(getenv func(string) string) (int, error) {
	on, err := serveLadybugEnabled(getenv)
	if err != nil || !on {
		return 0, err
	}
	return envInt(getenv, "SERVE_LADYBUG_BUFFER_MB", defaultServeLadybugBufferMB), nil
}

// serveLadybugEnabled reads SERVE_LADYBUG_ENABLED, the serve pod's opt-in for
// its own Ladybug replica. An unrecognised value is an error.
func serveLadybugEnabled(getenv func(string) string) (bool, error) {
	on, err := envswitch.Parse(getenv, "SERVE_LADYBUG_ENABLED")
	if err != nil {
		return false, fmt.Errorf("serveLadybugEnabled: %w", err)
	}
	return on, nil
}

func envInt(getenv func(string) string, key string, fallback int) int {
	if n, err := strconv.ParseInt(strings.TrimSpace(getenv(key)), 10, 32); err == nil && n > 0 {
		return int(n)
	}
	return fallback
}

func pgDSN(getenv func(string) string) string {
	return envOr(getenv, "DATABASE_URL", "postgres://graph:graph@localhost:5432/graph?sslmode=disable")
}

func chDSN(getenv func(string) string) string {
	return envOr(getenv, "CLICKHOUSE_URL", "clickhouse://graph:graph@localhost:9000/graph")
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

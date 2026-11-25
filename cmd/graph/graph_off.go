package main

// workerGraphOffWarning names what the worker runs without when the graph
// engine is not configured, or returns "" when it is. Logged once at startup:
// without it a source checkout that never set LADYBUG_INTERNAL_PORT reads as a
// fully featured worker.
func workerGraphOffWarning(getenv func(string) string) string {
	if getenv("LADYBUG_INTERNAL_PORT") != "" {
		return ""
	}
	return "worker: graph engine off (LADYBUG_INTERNAL_PORT unset): no internet-reach scoring signal, " +
		"saved-query detections and Cypher-targeted scan profiles fail, and serve has no graph RPC; " +
		"blast radius and peer findings read ClickHouse instead (docs/configuration.md#ladybug-graph-engine)"
}

// serveGraphOffWarning names what serve runs without when it has neither the
// worker's graph RPC nor its own replica, or when it dials the RPC without the
// secret the worker requires; it returns "" otherwise.
func serveGraphOffWarning(getenv func(string) string, replica bool) string {
	rpc := getenv("LADYBUG_RPC_URL") != ""
	if rpc && getenv("LADYBUG_RPC_SECRET") == "" {
		return "serve: LADYBUG_RPC_URL set but LADYBUG_RPC_SECRET unset: the worker serves no graph RPC " +
			"without the secret unless it runs with LADYBUG_RPC_INSECURE=true (dev only), so calls to it fail " +
			"(docs/configuration.md#ladybug-graph-engine)"
	}
	if replica || rpc {
		return ""
	}
	return "serve: no graph engine (LADYBUG_RPC_URL unset, SERVE_LADYBUG_ENABLED off): raw Cypher, " +
		"saved-query runs and NL-to-Cypher are unavailable; Explore traversals use the ClickHouse BFS " +
		"(docs/configuration.md#ladybug-graph-engine)"
}

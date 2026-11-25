package obs

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// Without an aggregate signal, a failed outbound alert delivery is only a log
// line plus notify.Channel's own DB column. These assertions pin the series
// that make it visible.
func TestObserveNotifyDelivery_CountsByChannelEventStatus(t *testing.T) {
	m := New()

	m.ObserveNotifyDelivery("chan-1", "slack", "finding", "ok")
	m.ObserveNotifyDelivery("chan-1", "slack", "finding", "error")
	m.ObserveNotifyDelivery("chan-1", "slack", "finding", "error")
	m.ObserveNotifyDelivery("chan-2", "webhook", "drift", "ok")

	require.Equal(t, 1.0, testutil.ToFloat64(m.notifyDelivery.WithLabelValues("chan-1", "finding", "ok")))
	require.Equal(t, 2.0, testutil.ToFloat64(m.notifyDelivery.WithLabelValues("chan-1", "finding", "error")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.notifyDelivery.WithLabelValues("chan-2", "drift", "ok")))

	// channel_type is deliberately not on the series: two channels of different
	// types produce independent series keyed only on channel_id/event_type/status,
	// and there is no way to recover "slack" vs "webhook" from the metric itself.
	require.Equal(t, 3, testutil.CollectAndCount(m.notifyDelivery))
}

// The whole obs package is nil-safe by convention (metrics are optional).
func TestObserveNotifyDelivery_NilSafe(t *testing.T) {
	var m *Metrics
	require.NotPanics(t, func() {
		m.ObserveNotifyDelivery("chan-1", "slack", "finding", "error")
	})
}

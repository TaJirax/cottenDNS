package client

import (
	"strings"
	"testing"
)

func TestFormatTrafficStatsMachineLineExposesEmbeddingTelemetry(t *testing.T) {
	line := formatTrafficStatsMachineLine(trafficStatsSnapshot{
		upBytesPerSecond:   101,
		upTotal:            202,
		downBytesPerSecond: 303,
		downTotal:          404,
		lossPerMille:       125,
		activeResolvers:    7,
		transportSummary:   "adaptive UDP=5 TCP=2 DoT=0 DoH=0",
		explorations:       8,
		restorations:       9,
		switches:           10,
		stripes:            11,
		redundancySaved:    12,
		txQueue:            13,
		encodedTXQueue:     14,
		rxQueue:            15,
		rxDrops:            16,
		txDrops:            17,
		recoveries:         18,
		streamDialFailures: 19,
		streamWriteFailure: 20,
	})

	for _, want := range []string{
		"WD_STATS ",
		"up_bps=101 up_total=202 down_bps=303 down_total=404",
		"loss_pm=125 resolvers=7",
		`transport="adaptive UDP=5 TCP=2 DoT=0 DoH=0"`,
		"explore=8 restore=9 switch=10 stripe=11 saved=12",
		"queue_tx=13 queue_encoded=14 queue_rx=15",
		"drop_rx=16 drop_tx=17 recoveries=18",
		"stream_dial_fail=19 stream_write_fail=20",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("telemetry line %q does not contain %q", line, want)
		}
	}
}

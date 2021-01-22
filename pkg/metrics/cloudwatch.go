package metrics

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"context"
	"io"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"
)

// Metrics manager
type Manager interface {
	// Runs the metric manager
	// It will sync the metrics every `interval` duration
	Run(ctx context.Context, interval time.Duration)
	// Returns a new Counter
	NewCounter(name string) Counter
	// Sync the metrics to the underlying system
	Sync() error
}

type CWEmbeddedMetricsManager struct {
	// mutex used for syncing
	mtx sync.Mutex
	// Space that keeps track of the counters
	counters *Space
	// The writer will the metrics will be written to
	writer io.Writer
	stream *jsoniter.Stream
	// Function that return the current time in milliseconds
	// Can be overwritten in unit tests
	timeFunc func() int64
}

// New returns a CWEmbeddedMetricsManager object that may be used to create metrics.
// Namespace is applied to all created metrics and maps to the CWEmbeddedMetricsManager namespace.
// Callers must ensure that regular calls to Send are performed, either
// manually or with one of the helper methods.
func NewCWEmbeddedMetrics(writer io.Writer) *CWEmbeddedMetricsManager {
	cwManager := &CWEmbeddedMetricsManager{
		writer:   writer,
		counters: NewSpace(),
		stream:   jsoniter.NewStream(jsoniter.ConfigDefault, nil, 8192),
		timeFunc: func() int64 {
			return time.Now().UnixNano() / 1e6
		},
	}
	return cwManager
}

// NewCounter returns a counter. Observations are aggregated and emitted once
// per write invocation.
// Panics if the client has been closed
func (c *CWEmbeddedMetricsManager) NewCounter(name string) Counter {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return &DimensionsCounter{
		name: name,
		obs:  c.counters.Observe,
	}
}

func (c *CWEmbeddedMetricsManager) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ticker.C:
			// nolint: errcheck
			c.Sync()
		case <-ctx.Done():
			// nolint: errcheck
			c.Sync()
			ticker.Stop()
			return
		}
	}
}

// Syncs metrics to the underlying system
// It will writer the metrics in the Embedded Metric Format
// https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
func (c *CWEmbeddedMetricsManager) Sync() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	var metrics []Metric
	var dimensions [][]string

	// Clear jsoniter stream buffer
	c.stream.Reset(nil)
	c.stream.WriteObjectStart()

	c.counters.Reset().Walk(func(name string, dms DimensionValues, values []float64) bool {
		// Write `"<metric name>" : <value>`
		c.stream.WriteObjectField(name)
		c.stream.WriteVal(sum(values))
		c.stream.WriteMore()

		// Write dimension values
		for i := 0; i+1 < len(dms); i = i + 2 {
			c.stream.WriteObjectField(dms[i])
			c.stream.WriteVal(dms[i+1])
			c.stream.WriteMore()
		}

		metrics = append(metrics, Metric{Name: name, Unit: "Count"})
		dimensions = append(dimensions, dimensionNames(dms...))

		return true
	})

	// If there are no metrics to be reported
	// Don't log anything
	if len(metrics) == 0 {
		return nil
	}

	const namespace = "Panther"
	embeddedMetric := EmbeddedMetric{
		Timestamp: c.timeFunc(),
		CloudWatchMetrics: []MetricDirectiveObject{
			{
				Namespace:  namespace,
				Dimensions: dimensions,
				Metrics:    metrics,
			},
		},
	}

	const rootElement = "_aws"
	c.stream.WriteObjectField(rootElement)
	c.stream.WriteVal(embeddedMetric)
	c.stream.WriteObjectEnd()
	// nolint: errcheck
	c.writer.Write(append(c.stream.Buffer(), '\n'))

	return nil
}

func sum(a []float64) float64 {
	var v float64
	for _, f := range a {
		v += f
	}
	return v
}

func dimensionNames(dimensionValues ...string) []string {
	dimensions := make([]string, len(dimensionValues)/2)
	for i, j := 0, 0; i < len(dimensionValues); i, j = i+2, j+1 {
		dimensions[j] = dimensionValues[i]
	}
	return dimensions
}

package panthermetrics

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
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/metrics"
)

// Global instance of metrics manager
var metricsManager MetricsManager

type MetricsManager interface {
	NewCounter(name string) *Counter
}

type CloudWatch struct {
	mtx      sync.RWMutex
	ticker   *time.Ticker
	counters *Space
	logger   *zap.Logger
}

// New returns a CloudWatch object that may be used to create metrics.
// Namespace is applied to all created metrics and maps to the CloudWatch namespace.
// Callers must ensure that regular calls to Send are performed, either
// manually or with one of the helper methods.
func SetupManager(log *zap.Logger) *CloudWatch {
	ticker := time.NewTicker(time.Minute)
	cwManager := &CloudWatch{
		logger:   log,
		counters: NewSpace(),
		ticker:   ticker,
	}
	Setup(cwManager)

	go func() {
		for range ticker.C {
			cwManager.mtx.RLock()
			cwManager.send()
			cwManager.mtx.RUnlock()
		}
	}()
	metricsManager = cwManager
	return cwManager
}

// NewCounter returns a counter. Observations are aggregated and emitted once
// per write invocation.
// Panics if the client has been closed
func (c *CloudWatch) NewCounter(name string) *Counter {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return &Counter{
		name: name,
		obs:  c.counters.Observe,
	}
}

func (c *CloudWatch) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.ticker.Stop()
	return c.send()
}

func (c *CloudWatch) send() error {
	now := time.Now()

	// Add each dimension to the list of top level fields
	var fields []zap.Field
	var mets []metrics.Metric
	var dims []metrics.DimensionSet

	c.counters.Reset().Walk(func(name string, dms DimensionValues, values []float64) bool {
		mets = append(mets, metrics.Metric{Name: name, Unit: "Count"})
		dims = append(dims, dimensionNames(dms...))
		fields = append(fields, zap.Any(name, sum(values)))
		for i := 0; i+1 < len(dms); i = i + 2 {
			fields = append(fields, zap.Any(dms[i], dms[i+1]))
		}
		return true
	})

	// If there are no metrics to be reported
	// Don't log anything
	if len(fields) == 0 {
		return nil
	}

	// Construct the embedded metric metadata object per AWS standards
	// https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
	const namespace = "Panther"
	embeddedMetric := metrics.EmbeddedMetric{
		Timestamp: now.UnixNano() / 10e6,
		CloudWatchMetrics: []metrics.MetricDirectiveObject{
			{
				Namespace:  namespace,
				Dimensions: dims,
				Metrics:    mets,
			},
		},
	}

	const rootElement = "_aws"
	fields = append(fields, zap.Any(rootElement, embeddedMetric))

	const metricField = "metric"
	c.logger.Info(metricField, fields...)

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

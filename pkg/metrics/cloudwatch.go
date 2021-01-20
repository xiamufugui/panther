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
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/metrics/internal"
)

type CloudWatch struct {
	mtx      sync.RWMutex
	ticker   *time.Ticker
	counters *internal.Space
	logger   *zap.Logger
}

// New returns a CloudWatch object that may be used to create metrics.
// Namespace is applied to all created metrics and maps to the CloudWatch namespace.
// Callers must ensure that regular calls to Send are performed, either
// manually or with one of the helper methods.
func NewCloudWatch(log *zap.Logger, duration time.Duration) *CloudWatch {
	return &CloudWatch{
		logger:   log,
		counters: internal.NewSpace(),
		ticker: time.NewTicker(duration),
	}
}

// NewCounter returns a counter. Observations are aggregated and emitted once
// per write invocation.
func (c *CloudWatch) NewCounter(name string) *Counter {
	return &Counter{
		name: name,
		obs:  c.counters.Observe,
	}
}

func (c *CloudWatch) Close() error {
	c.ticker.Stop()
	return c.logger.Sync()
}

func (c *CloudWatch) Sync() error {
	return nil
}

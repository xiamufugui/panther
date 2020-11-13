package glueschema

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
	"fmt"
	"math/big"
	"reflect"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

var defaultMappings = map[reflect.Type]Type{
	reflect.TypeOf(time.Time{}):           TypeTimestamp,
	reflect.TypeOf(big.Int{}):             TypeBigInt,
	reflect.TypeOf(jsoniter.RawMessage{}): TypeString,
	reflect.TypeOf(null.Float64{}):        TypeDouble,
	reflect.TypeOf(null.Float32{}):        TypeFloat,
	reflect.TypeOf(null.Int64{}):          TypeBigInt,
	reflect.TypeOf(null.Int32{}):          TypeInt,
	reflect.TypeOf(null.Int16{}):          TypeSmallInt,
	reflect.TypeOf(null.Int8{}):           TypeTinyInt,
	reflect.TypeOf(null.Uint64{}):         TypeBigInt,
	reflect.TypeOf(null.Uint32{}):         TypeBigInt,
	reflect.TypeOf(null.Uint16{}):         TypeInt,
	reflect.TypeOf(null.Uint8{}):          TypeSmallInt,
	reflect.TypeOf(null.String{}):         TypeString,
	reflect.TypeOf(null.NonEmpty{}):       TypeString,
	reflect.TypeOf(null.Bool{}):           TypeBool,
}

func MustRegisterMapping(from reflect.Type, to Type) {
	if err := RegisterMapping(from, to); err != nil {
		panic(err)
	}
}

func RegisterMapping(from reflect.Type, to Type) error {
	if typ, duplicate := defaultMappings[from]; duplicate {
		// This is an original error, stack should be added at the caller
		return fmt.Errorf("duplicate mapping %q", typ)
	}
	defaultMappings[from] = to
	return nil
}

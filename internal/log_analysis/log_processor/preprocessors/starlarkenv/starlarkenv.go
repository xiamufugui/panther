package starlarkenv

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

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/preprocessors/starlarkenv/fastmatch"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/preprocessors/starlarkenv/json"
)

var (
	once sync.Once
	env  starlark.StringDict
)

func Load() starlark.StringDict {
	once.Do(func() {
		env = starlark.StringDict{
			"json": starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
				"loads": starlark.NewBuiltin("loads", json.Loads),
				"dumps": starlark.NewBuiltin("dumps", json.Dumps),
			}),
			"fastmatch": starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
				"compile": starlark.NewBuiltin("combile", fastmatch.Compile),
			}),
		}
		env.Freeze()
	})
	return env
}

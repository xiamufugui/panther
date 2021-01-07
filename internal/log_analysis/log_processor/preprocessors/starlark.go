package preprocessors

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
	"errors"
	"strings"

	"go.starlark.net/starlark"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/preprocessors/starlarkenv"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/preprocessors/starlarkenv/json"
)

type StarlarkConfig struct {
	Code string `json:"code" yaml:"code" description:"Starlark parser code"`
}

func (config StarlarkConfig) BuildPreprocessor() (Interface, error) {
	thread := starlark.Thread{
		Name:  "preprocessor",
		Print: nopPrint,
		Load:  loadFail,
	}
	env, err := starlark.ExecFile(&thread, "parser.star", config.Code, starlarkenv.Load())
	if err != nil {
		return nil, err
	}
	parse := env["parse"]
	switch p := parse.(type) {
	case *starlark.Function:
		if p.HasKwargs() || p.HasVarargs() || p.NumParams() != 1 {
			return nil, errors.New("invalid parse function signature")
		}
		p.Freeze()
		return &starlarkPreprocessor{
			thread:     &thread,
			preprocess: p,
			env:        env,
		}, nil
	default:
		return nil, errors.New("no parse function defined")
	}
}

type starlarkPreprocessor struct {
	thread     *starlark.Thread
	preprocess *starlark.Function
	env        starlark.StringDict
}

func (p *starlarkPreprocessor) PreProcessLog(entry string) (string, error) {
	args := starlark.Tuple{
		starlark.String(entry),
	}
	result, err := starlark.Call(p.thread, p.preprocess, args, nil)
	if err != nil {
		return "", err
	}
	switch r := result.(type) {
	case starlark.String:
		return r.GoString(), nil
	default:
		w := strings.Builder{}
		w.Grow(4096)
		if err := json.Printf(&w, r); err != nil {
			return "", err
		}
		return w.String(), nil
	}
}

var (
	errModuleNotFound = errors.New("module not found")
)

func nopPrint(*starlark.Thread, string) {}

func loadFail(*starlark.Thread, string) (starlark.StringDict, error) {
	return nil, errModuleNotFound
}

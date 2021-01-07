package fastmatch

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
	"hash/maphash"
	"strconv"

	"go.starlark.net/starlark"

	"github.com/panther-labs/panther/pkg/x/fastmatch"
)

type FastMatch struct {
	src     string
	name    string
	pattern *fastmatch.Pattern
	match   []string
}

var _ starlark.Callable = (*FastMatch)(nil)

func (p *FastMatch) String() string {
	return p.src
}

func (*FastMatch) Type() string {
	return "fastmatch"
}

func (*FastMatch) Freeze() {
}

func (p *FastMatch) Truth() starlark.Bool {
	return false
}

func (p *FastMatch) Hash() (uint32, error) {
	return starlark.String(p.src).Hash()
}

func (p *FastMatch) Name() string {
	return p.name
}

func (p *FastMatch) CallInternal(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input string
	if err := starlark.UnpackPositionalArgs("fastmatch", args, kwargs, 2, &input); err != nil {
		return starlark.None, err
	}
	match, err := p.pattern.MatchString(p.match[:0], input)
	if err != nil {
		return starlark.None, nil
	}
	p.match = match
	dict := starlark.NewDict(len(match) / 2)
	for len(match) >= 2 {
		k, v, tail := match[0], match[1], match[2:]
		match = tail
		dict.SetKey(starlark.String(k), starlark.String(v))
	}
	return dict, nil
}

func Compile(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var src string
	if err := starlark.UnpackPositionalArgs("fastmatch.compile", args, kwargs, 1, &src); err != nil {
		return nil, err
	}
	pattern, err := fastmatch.Compile(src)
	if err != nil {
		return nil, err
	}
	h := maphash.Hash{}
	h.WriteString(src)
	name := "fastmatch_" + strconv.FormatUint(h.Sum64(), 16)
	return &FastMatch{
		src:     src,
		name:    name,
		pattern: pattern,
	}, nil
}

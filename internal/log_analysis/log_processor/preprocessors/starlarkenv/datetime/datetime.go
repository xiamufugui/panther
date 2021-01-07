package datetime

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
	"time"

	"go.starlark.net/starlark"
)

type DateTime time.Time

func (d DateTime) String() string {
	return time.Time(d).String()
}

func (d DateTime) Type() string {
	return "datetime"
}

func (d DateTime) Freeze() {
}

func (d DateTime) Truth() starlark.Bool {
	return starlark.Bool(!time.Time(d).IsZero())
}

func (d DateTime) Hash() (uint32, error) {
	panic("implement me")
}

func (d DateTime) Attr(name string) (starlark.Value, error) {
	proto, ok := dateTimeProto[name]
	if !ok {
		return nil, nil
	}
	return proto.BindReceiver(d), nil
}

func (d DateTime) AttrNames() []string {
	return dateTimeMethods
}

var dateTimeProto = map[string]*starlark.Builtin{
	"format": starlark.NewBuiltin("format", func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var layout = time.RFC3339
		if err := starlark.UnpackArgs("time.format", args, kwargs, "layout?", layout); err != nil {
			return starlark.None, err
		}
		recv := fn.Receiver().(DateTime)
		return starlark.String(time.Time(recv).Format(layout)), nil
	}),
}
var dateTimeMethods = func() []string {
	names := make([]string, 0, len(dateTimeProto))
	for name := range dateTimeProto {
		names = append(names, name)
	}
	return names
}()

var _ starlark.HasAttrs = DateTime{}

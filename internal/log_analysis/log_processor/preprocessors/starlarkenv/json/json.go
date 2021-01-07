package json

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
	"encoding/json"
	"errors"
	"io"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"go.starlark.net/starlark"
)

func Loads(th *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input string
	if err := starlark.UnpackPositionalArgs("parse_json", args, kwargs, 1, &input); err != nil {
		return nil, err
	}
	iter := iteratorFromThread(th)
	iter.Reset(strings.NewReader(input))
	value := parseValue(iter)
	if err := iter.Error; err != nil {
		return nil, err
	}
	return value, nil
}

func parseValue(iter *jsoniter.Iterator) starlark.Value {
	switch iter.WhatIsNext() {
	case jsoniter.ObjectValue:
		dict := starlark.NewDict(16)
		for key := iter.ReadObject(); key != ""; key = iter.ReadObject() {
			value := parseValue(iter)
			if value == nil {
				return nil
			}
			dict.SetKey(starlark.String(key), value)
		}
		return dict
	case jsoniter.StringValue:
		value := iter.ReadString()
		return starlark.String(value)
	case jsoniter.NumberValue:
		value := iter.ReadFloat64()
		return starlark.Float(value)
	case jsoniter.BoolValue:
		value := iter.ReadBool()
		return starlark.Bool(value)
	case jsoniter.NilValue:
		iter.Skip()
		return starlark.None
	case jsoniter.ArrayValue:
		elements := make([]starlark.Value, 0, 16)
		for iter.ReadArray() {
			el := parseValue(iter)
			if el == nil {
				return nil
			}
			elements = append(elements, el)
		}
		return starlark.NewList(elements)
	default:
		return nil
	}
}

func Dumps(th *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackPositionalArgs("dump_json", args, kwargs, 1, &value); err != nil {
		return nil, err
	}
	w := strings.Builder{}
	w.Grow(4096)
	stream := streamFromThread(th)
	stream.Reset(&w)
	if err := dumpValue(stream, value); err != nil {
		return nil, err
	}
	if err := stream.Error; err != nil {
		return nil, err
	}
	return starlark.String(w.String()), nil
}

func Printf(w io.Writer, value starlark.Value) error {
	stream := jsoniter.ConfigDefault.BorrowStream(w)
	defer stream.Pool().ReturnStream(stream)
	if err := dumpValue(stream, value); err != nil {
		return err
	}
	if err := stream.Flush(); err != nil {
		return err
	}
	return nil
}

func dumpValue(stream *jsoniter.Stream, value starlark.Value) error {
	switch value := value.(type) {
	case *starlark.Dict:
		return dumpDict(stream, value)
	case *starlark.List:
		return dumpList(stream, value)
	case starlark.Tuple:
		return dumpList(stream, value)
	case starlark.String:
		stream.WriteString(value.GoString())
	case starlark.Bool:
		stream.WriteBool(bool(value))
	case starlark.Float:
		stream.WriteFloat64(float64(value))
	case starlark.Int:
		n := value.BigInt()
		stream.WriteRaw(n.String())
	case starlark.NoneType:
		stream.WriteNil()
	case json.Marshaler:
		stream.WriteVal(value)
	default:
		return errors.New("invalid type")
	}
	return stream.Error
}

func dumpList(stream *jsoniter.Stream, list starlark.Indexable) error {
	stream.WriteArrayStart()
	n := list.Len()
	for i := 0; i < n; i++ {
		if i > 0 {
			stream.WriteMore()
		}
		v := list.Index(i)
		if err := dumpValue(stream, v); err != nil {
			return err
		}
	}
	stream.WriteArrayEnd()
	return nil
}

func dumpDict(stream *jsoniter.Stream, dict *starlark.Dict) error {
	stream.WriteObjectStart()
	for i, item := range dict.Items() {
		if i > 0 {
			stream.WriteMore()
		}
		k, v := item.Index(0), item.Index(1)
		key, ok := k.(starlark.String)
		if !ok {
			return errors.New("invalid key")
		}
		stream.WriteObjectField(key.GoString())
		if err := dumpValue(stream, v); err != nil {
			return err
		}
	}
	stream.WriteObjectEnd()
	return nil
}

func iteratorFromThread(th *starlark.Thread) *jsoniter.Iterator {
	const key = "jsoniter"
	if iter, ok := th.Local(key).(*jsoniter.Iterator); ok {
		iter.Error = nil
		return iter
	}
	iter := jsoniter.Parse(jsoniter.ConfigDefault, nil, 4096)
	th.SetLocal(key, iter)
	return iter
}

func streamFromThread(th *starlark.Thread) *jsoniter.Stream {
	const key = "jsonstream"
	if stream, ok := th.Local(key).(*jsoniter.Stream); ok {
		stream.Error = nil
		return stream
	}
	stream := jsoniter.NewStream(jsoniter.ConfigDefault, nil, 4096)
	th.SetLocal(key, stream)
	return stream
}

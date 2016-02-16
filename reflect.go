package framework

import (
	"errors"
	"reflect"
	"strings"
)

var (
	ErrTypeError = errors.New("type error")
)

func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

func ifSliceToStrSlice(v []interface{}) ([]string, error) {
	var list []string
	for i := range v {
		s, ok := v[i].(string)
		if !ok {
			return list, ErrTypeError
		}
		list = append(list, s)
	}

	return list, nil
}

func hasJSONOption(key, opts string) bool {
	if len(opts) == 0 {
		return false
	}
	for opts != "" {
		var next string
		i := strings.Index(opts, ",")
		if i >= 0 {
			opts, next = opts[:i], opts[i+1:]
		}
		if opts == key {
			return true
		}
		opts = next
	}
	return false
}

func parseJSONTag(tag string) (string, string) {
	if idx := strings.Index(tag, ","); idx != -1 {
		return tag[:idx], tag[idx+1:]
	}
	return tag, ""
}

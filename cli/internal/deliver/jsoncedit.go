package deliver

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/tailscale/hujson"
)

// JSON-with-comments config files are edited member by member: the one
// member amctl owns is added, replaced or removed with indentation copied from
// its siblings, and every other byte stays as it was. Each edit is re-parsed
// and must change exactly that member, or it is refused.

// jsoncGet returns the standard JSON at path (object member names), nil when
// any step is absent.
func jsoncGet(doc []byte, path ...string) (any, error) {
	if strings.TrimSpace(string(doc)) == "" {
		return nil, nil
	}
	root, err := hujson.Parse(doc)
	if err != nil {
		return nil, err
	}
	v := &root
	for _, name := range path {
		obj, ok := v.Value.(*hujson.Object)
		if !ok {
			return nil, nil
		}
		i := memberIndex(obj, name)
		if i < 0 {
			return nil, nil
		}
		v = &obj.Members[i].Value
	}
	return standard(*v)
}

func standard(v hujson.Value) (any, error) {
	c := v.Clone()
	c.Standardize()
	var out any
	if err := json.Unmarshal(c.Pack(), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// jsoncSet sets the member at path to value, creating parent objects.
func jsoncSet(doc []byte, value any, path ...string) ([]byte, error) {
	if strings.TrimSpace(string(doc)) == "" {
		doc = []byte("{}\n")
	}
	root, err := hujson.Parse(doc)
	if err != nil {
		return nil, err
	}
	before, err := standard(root)
	if err != nil {
		return nil, err
	}
	obj, ok := root.Value.(*hujson.Object)
	if !ok {
		return nil, errors.New("the file is not a JSON object")
	}
	indent, unit := "", indentUnit(obj)
	for depth, name := range path {
		last := depth == len(path)-1
		i := memberIndex(obj, name)
		memberIndent := indent + unit
		if i >= 0 && last {
			b, merr := marshalIndentJSON(value, memberIndent, unit)
			if merr != nil {
				return nil, merr
			}
			nv, perr := hujson.Parse(b)
			if perr != nil {
				return nil, perr
			}
			old := obj.Members[i].Value
			nv.BeforeExtra, nv.AfterExtra = old.BeforeExtra, old.AfterExtra
			obj.Members[i].Value = nv
			break
		}
		if i >= 0 {
			next, isObj := obj.Members[i].Value.Value.(*hujson.Object)
			if !isObj {
				return nil, fmt.Errorf("%q is not an object", strings.Join(path[:depth+1], "."))
			}
			obj, indent = next, memberIndent
			continue
		}
		v := value
		for j := len(path) - 1; j > depth; j-- {
			v = map[string]any{path[j]: v}
		}
		if err := appendMember(obj, name, v, indent, unit); err != nil {
			return nil, err
		}
		break
	}
	root.UpdateOffsets()

	want := setIn(before, value, path)
	return checkJSONC(root.Pack(), want)
}

// jsoncRemove removes the member at path; a parent object left empty by the
// removal is removed too, so an add followed by a remove restores the file.
func jsoncRemove(doc []byte, path ...string) ([]byte, error) {
	if strings.TrimSpace(string(doc)) == "" {
		return doc, nil
	}
	root, err := hujson.Parse(doc)
	if err != nil {
		return nil, err
	}
	before, err := standard(root)
	if err != nil {
		return nil, err
	}
	objs := []*hujson.Object{}
	v := &root
	for _, name := range path {
		obj, ok := v.Value.(*hujson.Object)
		if !ok {
			return doc, nil
		}
		i := memberIndex(obj, name)
		if i < 0 {
			return doc, nil
		}
		objs = append(objs, obj)
		v = &obj.Members[i].Value
	}
	for depth := len(path) - 1; depth >= 0; depth-- {
		removeMember(objs[depth], memberIndex(objs[depth], path[depth]))
		if depth == 0 || len(objs[depth].Members) > 0 {
			break
		}
	}
	root.UpdateOffsets()

	want := removeIn(before, path)
	return checkJSONC(root.Pack(), want)
}

func checkJSONC(out []byte, want any) ([]byte, error) {
	v, err := hujson.Parse(out)
	if err != nil {
		return nil, fmt.Errorf("the edited file would not parse: %w", err)
	}
	got, err := standard(v)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(got, want) {
		return nil, errors.New("the edit would change more than its own entry; edit the file by hand")
	}
	return out, nil
}

func setIn(doc, value any, path []string) any {
	m, _ := doc.(map[string]any)
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	if len(path) == 1 {
		out[path[0]] = roundTrip(value)
		return out
	}
	out[path[0]] = setIn(out[path[0]], value, path[1:])
	return out
}

func removeIn(doc any, path []string) any {
	m, _ := doc.(map[string]any)
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	if len(path) == 1 {
		delete(out, path[0])
		return out
	}
	sub := removeIn(out[path[0]], path[1:])
	if sm, _ := sub.(map[string]any); len(sm) == 0 {
		delete(out, path[0])
	} else {
		out[path[0]] = sub
	}
	return out
}

func roundTrip(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return v
	}
	return out
}

func memberIndex(obj *hujson.Object, name string) int {
	for i := range obj.Members {
		var n string
		if lit, ok := obj.Members[i].Name.Value.(hujson.Literal); ok && json.Unmarshal(lit, &n) == nil && n == name {
			return i
		}
	}
	return -1
}

func indentUnit(obj *hujson.Object) string {
	if len(obj.Members) > 0 {
		if ind := lastLineIndent(string(obj.Members[0].Name.BeforeExtra)); ind != "" {
			return ind
		}
	}
	return "  "
}

func lastLineIndent(extra string) string {
	i := strings.LastIndexByte(extra, '\n')
	if i < 0 {
		return ""
	}
	tail := extra[i+1:]
	if strings.Trim(tail, " \t") != "" {
		return ""
	}
	return tail
}

func appendMember(obj *hujson.Object, name string, value any, indent, unit string) error {
	memberIndent := indent + unit
	inline := len(obj.Members) > 0 && !strings.Contains(string(obj.AfterExtra), "\n")
	b, err := encodeFor(value, inline, memberIndent, unit)
	if err != nil {
		return err
	}
	nv, err := hujson.Parse(b)
	if err != nil {
		return err
	}
	nameLit, err := json.Marshal(name)
	if err != nil {
		return err
	}

	// Whatever sat before the closing brace (a comment after the last member,
	// say) stays where it was; the new member starts on the next line.
	after := string(obj.AfterExtra)
	head, tail := after, indent
	if i := strings.LastIndexByte(after, '\n'); i >= 0 {
		head, tail = after[:i], after[i+1:]
	}
	m := hujson.ObjectMember{
		Name:  hujson.Value{BeforeExtra: hujson.Extra(head + "\n" + memberIndent), Value: hujson.Literal(nameLit)},
		Value: hujson.Value{BeforeExtra: hujson.Extra(" "), Value: nv.Value},
	}
	if inline {
		m.Name.BeforeExtra = hujson.Extra(" ")
	}
	if n := len(obj.Members); n > 0 && obj.Members[n-1].Value.AfterExtra != nil {
		m.Value.AfterExtra = hujson.Extra("") // keep the trailing comma
	}
	obj.Members = append(obj.Members, m)
	if !inline {
		obj.AfterExtra = hujson.Extra("\n" + tail)
	}
	return nil
}

// encodeFor renders a value for a container written on one line (compact)
// or one member per line (indented like its siblings).
func encodeFor(value any, inline bool, indent, unit string) ([]byte, error) {
	if inline {
		return marshalJSON(value)
	}
	return marshalIndentJSON(value, indent, unit)
}

func removeMember(obj *hujson.Object, i int) {
	m := obj.Members[i]
	last := i == len(obj.Members)-1
	obj.Members = append(obj.Members[:i], obj.Members[i+1:]...)
	if !last {
		return
	}
	if before := string(m.Name.BeforeExtra); strings.Contains(before, "\n") {
		obj.AfterExtra = hujson.Extra(before[:strings.LastIndexByte(before, '\n')] + string(obj.AfterExtra))
	}
	if n := len(obj.Members); n > 0 {
		prev := &obj.Members[n-1].Value
		switch {
		case m.Value.AfterExtra != nil && prev.AfterExtra == nil:
			prev.AfterExtra = hujson.Extra("")
		case m.Value.AfterExtra == nil && prev.AfterExtra != nil:
			obj.AfterExtra = append(prev.AfterExtra, obj.AfterExtra...)
			prev.AfterExtra = nil
		}
	} else if strings.TrimSpace(string(obj.AfterExtra)) == "" {
		obj.AfterExtra = nil
	}
}

// jsoncAppend appends value to the array at path, creating the array (and
// its parent objects) when it is absent.
func jsoncAppend(doc []byte, value any, path ...string) ([]byte, error) {
	cur, err := jsoncGet(doc, path...)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return jsoncSet(doc, []any{value}, path...)
	}
	return editArray(doc, path, func(arr *hujson.Array, indent, unit string, list []any) ([]any, error) {
		if err := appendElement(arr, value, indent, unit); err != nil {
			return nil, err
		}
		return append(list, roundTrip(value)), nil
	})
}

func jsoncSetElem(doc []byte, i int, value any, path ...string) ([]byte, error) {
	return editArray(doc, path, func(arr *hujson.Array, indent, unit string, list []any) ([]any, error) {
		b, err := marshalIndentJSON(value, indent+unit, unit)
		if err != nil {
			return nil, err
		}
		nv, err := hujson.Parse(b)
		if err != nil {
			return nil, err
		}
		nv.BeforeExtra, nv.AfterExtra = arr.Elements[i].BeforeExtra, arr.Elements[i].AfterExtra
		arr.Elements[i] = nv
		list[i] = roundTrip(value)
		return list, nil
	})
}

// jsoncRemoveElem removes element i of the array at path; an array left
// empty is removed with its emptied parents, as jsoncRemove does.
func jsoncRemoveElem(doc []byte, i int, path ...string) ([]byte, error) {
	cur, err := jsoncGet(doc, path...)
	if err != nil {
		return nil, err
	}
	if list, _ := cur.([]any); len(list) == 1 && i == 0 {
		return jsoncRemove(doc, path...)
	}
	return editArray(doc, path, func(arr *hujson.Array, _, _ string, list []any) ([]any, error) {
		removeElement(arr, i)
		return append(list[:i:i], list[i+1:]...), nil
	})
}

func editArray(doc []byte, path []string, change func(arr *hujson.Array, indent, unit string, list []any) ([]any, error)) ([]byte, error) {
	root, err := hujson.Parse(doc)
	if err != nil {
		return nil, err
	}
	before, err := standard(root)
	if err != nil {
		return nil, err
	}
	obj, ok := root.Value.(*hujson.Object)
	if !ok {
		return nil, errors.New("the file is not a JSON object")
	}
	unit := indentUnit(obj)
	indent := ""
	v := &root
	for _, name := range path {
		o, isObj := v.Value.(*hujson.Object)
		if !isObj {
			return nil, fmt.Errorf("%q is not an object", strings.Join(path, "."))
		}
		i := memberIndex(o, name)
		if i < 0 {
			return nil, fmt.Errorf("%q is absent", strings.Join(path, "."))
		}
		v = &o.Members[i].Value
		indent += unit
	}
	arr, ok := v.Value.(*hujson.Array)
	if !ok {
		return nil, fmt.Errorf("%q is not an array", strings.Join(path, "."))
	}
	cur, err := standard(*v)
	if err != nil {
		return nil, err
	}
	list, _ := cur.([]any)
	list, err = change(arr, indent, unit, append([]any(nil), list...))
	if err != nil {
		return nil, err
	}
	root.UpdateOffsets()
	return checkJSONC(root.Pack(), setIn(before, list, path))
}

func appendElement(arr *hujson.Array, value any, indent, unit string) error {
	elemIndent := indent + unit
	inline := len(arr.Elements) > 0 && !strings.Contains(string(arr.AfterExtra), "\n")
	b, err := encodeFor(value, inline, elemIndent, unit)
	if err != nil {
		return err
	}
	nv, err := hujson.Parse(b)
	if err != nil {
		return err
	}
	after := string(arr.AfterExtra)
	head, tail := after, indent
	if i := strings.LastIndexByte(after, '\n'); i >= 0 {
		head, tail = after[:i], after[i+1:]
	}
	nv.BeforeExtra = hujson.Extra(head + "\n" + elemIndent)
	if inline {
		nv.BeforeExtra = hujson.Extra(" ")
	}
	nv.AfterExtra = nil
	if n := len(arr.Elements); n > 0 && arr.Elements[n-1].AfterExtra != nil {
		nv.AfterExtra = hujson.Extra("")
	}
	arr.Elements = append(arr.Elements, nv)
	if !inline {
		arr.AfterExtra = hujson.Extra("\n" + tail)
	}
	return nil
}

func removeElement(arr *hujson.Array, i int) {
	e := arr.Elements[i]
	last := i == len(arr.Elements)-1
	arr.Elements = append(arr.Elements[:i], arr.Elements[i+1:]...)
	if !last {
		return
	}
	if before := string(e.BeforeExtra); strings.Contains(before, "\n") {
		arr.AfterExtra = hujson.Extra(before[:strings.LastIndexByte(before, '\n')] + string(arr.AfterExtra))
	}
	if n := len(arr.Elements); n > 0 {
		prev := &arr.Elements[n-1]
		switch {
		case e.AfterExtra != nil && prev.AfterExtra == nil:
			prev.AfterExtra = hujson.Extra("")
		case e.AfterExtra == nil && prev.AfterExtra != nil:
			arr.AfterExtra = append(prev.AfterExtra, arr.AfterExtra...)
			prev.AfterExtra = nil
		}
	}
}

package iac

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Resource is a Terraform `resource` block flattened to the literal values a
// check needs. Attributes whose expressions reference variables/other resources
// cannot be evaluated statically and are simply absent — checks treat "absent"
// conservatively (they never assume a value they could not read).
type Resource struct {
	Type    string // e.g. "aws_s3_bucket"
	Name    string // e.g. "assets"
	Address string // "<Type>.<Name>"
	File    string
	Attrs   map[string]Value
	Blocks  []Block // nested blocks, e.g. ingress {...}
}

// Block is a nested block inside a resource (ingress, server_side_encryption…).
type Block struct {
	Type  string
	Attrs map[string]Value
}

// Value is a best-effort literal reading of an attribute expression. Only one of
// the typed fields is meaningful, per Kind. Kind is empty when the expression was
// not a static literal (a variable/interpolation) — the attribute is then treated
// as unknown rather than guessed.
type Value struct {
	Kind string // "string" | "bool" | "number" | "list" | ""
	Str  string
	Bool bool
	Num  int64
	List []string
}

// ParseHCL parses one Terraform file and returns its resource blocks. A syntax
// error fails the whole file (returned as error); a resource whose attributes
// can't be statically evaluated still parses (those attributes are omitted).
func ParseHCL(filename, content string) ([]Resource, error) {
	f, diags := hclsyntax.ParseConfig([]byte(content), filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse %s: %s", filename, diags.Error())
	}
	body, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("parse %s: unexpected body type", filename)
	}

	var out []Resource
	for _, blk := range body.Blocks {
		if blk.Type != "resource" || len(blk.Labels) != 2 {
			continue
		}
		r := Resource{
			Type:    blk.Labels[0],
			Name:    blk.Labels[1],
			Address: blk.Labels[0] + "." + blk.Labels[1],
			File:    filename,
			Attrs:   attrsOf(blk.Body),
		}
		for _, nb := range blk.Body.Blocks {
			r.Blocks = append(r.Blocks, Block{Type: nb.Type, Attrs: attrsOf(nb.Body)})
		}
		out = append(out, r)
	}
	return out, nil
}

// attrsOf evaluates a body's attributes to literal Values, skipping any that
// reference variables (expr.Value with a nil context errors on those).
func attrsOf(body *hclsyntax.Body) map[string]Value {
	attrs := map[string]Value{}
	for name, attr := range body.Attributes {
		v, diags := attr.Expr.Value(nil)
		if diags.HasErrors() || v.IsNull() || !v.IsKnown() {
			continue
		}
		if cv, ok := toValue(v); ok {
			attrs[name] = cv
		}
	}
	return attrs
}

func toValue(v cty.Value) (Value, bool) {
	switch {
	case v.Type() == cty.String:
		return Value{Kind: "string", Str: v.AsString()}, true
	case v.Type() == cty.Bool:
		return Value{Kind: "bool", Bool: v.True()}, true
	case v.Type() == cty.Number:
		bf := v.AsBigFloat()
		i, _ := bf.Int64()
		return Value{Kind: "number", Num: i}, true
	case v.CanIterateElements() && (v.Type().IsTupleType() || v.Type().IsListType() || v.Type().IsSetType()):
		var list []string
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			if ev.Type() == cty.String && ev.IsKnown() && !ev.IsNull() {
				list = append(list, ev.AsString())
			}
		}
		return Value{Kind: "list", List: list}, true
	}
	return Value{}, false
}

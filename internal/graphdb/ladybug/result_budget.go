package ladybug

// #include "lbug.h"
// #include <string.h>
import "C"

import (
	"errors"
	"fmt"
)

// ErrResultLimit means a native result cannot be converted within the budget.
var ErrResultLimit = errors.New("ladybug: result conversion budget exceeded")

// ResultBudget is consumed across all rows of one caller-supplied query.
// Bytes conservatively includes JSON escaping and Go container overhead.
type ResultBudget struct {
	Bytes              int
	Values             int
	MaxCellBytes       int
	MaxCollectionItems int
	MaxDepth           int
}

func (b *ResultBudget) spend(bytes, values int) error {
	if b == nil || bytes < 0 || values < 0 || bytes > b.Bytes || values > b.Values {
		return ErrResultLimit
	}
	b.Bytes -= bytes
	b.Values -= values
	return nil
}

func (b *ResultBudget) text(s *C.char) error {
	if s == nil {
		return nil
	}
	if b.MaxCellBytes <= 0 {
		return ErrResultLimit
	}
	n := C.strnlen(s, C.size_t(b.MaxCellBytes+1))
	if uint64(n) > uint64(b.MaxCellBytes) {
		return ErrResultLimit
	}
	return b.spend(int(n)*6, 0)
}

// GetAsMapBounded checks native sizes before allocating Go slices/maps/strings.
// Engine execution has already happened; this bounds conversion and output,
// not the engine's own query workspace.
func (tuple *FlatTuple) GetAsMapBounded(b *ResultBudget) (map[string]any, error) {
	if b == nil || b.MaxCellBytes <= 0 || b.MaxCellBytes > 1<<30 || b.MaxDepth <= 0 {
		return nil, ErrResultLimit
	}
	columns := tuple.queryResult.GetNumberOfColumns()
	if columns > 256 {
		return nil, ErrResultLimit
	}
	for _, name := range tuple.queryResult.GetColumnNames() {
		if len(name) > b.MaxCellBytes {
			return nil, ErrResultLimit
		}
		if err := b.spend(len(name)*6, 0); err != nil {
			return nil, err
		}
	}
	for i := uint64(0); i < uint64(columns); i++ {
		var v C.lbug_value
		if C.lbug_flat_tuple_get_value(&tuple.cFlatTuple, C.uint64_t(i), &v) != C.LbugSuccess {
			return nil, fmt.Errorf("result budget: cannot read column %d", i)
		}
		err := b.check(v, 0)
		C.lbug_value_destroy(&v)
		if err != nil {
			return nil, err
		}
	}
	return tuple.GetAsMap()
}

func (b *ResultBudget) check(v C.lbug_value, depth int) error {
	if depth > b.MaxDepth {
		return ErrResultLimit
	}
	if err := b.spend(64, 1); err != nil {
		return err
	}
	if C.lbug_value_is_null(&v) {
		return nil
	}
	var typ C.lbug_logical_type
	C.lbug_value_get_data_type(&v, &typ)
	defer C.lbug_data_type_destroy(&typ)
	kind := C.lbug_data_type_get_id(&typ)
	var size C.uint64_t
	var status C.lbug_state
	switch kind {
	case C.LBUG_STRING:
		var s *C.char
		if C.lbug_value_get_string(&v, &s) != C.LbugSuccess {
			return fmt.Errorf("result budget: cannot read string")
		}
		defer C.lbug_destroy_string(s)
		return b.text(s)
	case C.LBUG_BLOB:
		var data *C.uint8_t
		if C.lbug_value_get_blob(&v, &data, &size) != C.LbugSuccess {
			return fmt.Errorf("result budget: cannot read blob")
		}
		defer C.lbug_destroy_blob(data)
		if uint64(size) > uint64(b.MaxCellBytes) {
			return ErrResultLimit
		}
		return b.spend(int(size)*6, 0)
	case C.LBUG_LIST:
		status = C.lbug_value_get_list_size(&v, &size)
	case C.LBUG_ARRAY:
		status = C.lbug_data_type_get_num_elements_in_array(&typ, &size)
	case C.LBUG_STRUCT, C.LBUG_UNION:
		status = C.lbug_value_get_struct_num_fields(&v, &size)
	case C.LBUG_MAP:
		status = C.lbug_value_get_map_size(&v, &size)
	case C.LBUG_NODE:
		status = C.lbug_node_val_get_property_size(&v, &size)
	case C.LBUG_REL:
		status = C.lbug_rel_val_get_property_size(&v, &size)
	case C.LBUG_RECURSIVE_REL:
		for _, nodes := range []bool{true, false} {
			var child C.lbug_value
			if nodes {
				status = C.lbug_value_get_recursive_rel_node_list(&v, &child)
			} else {
				status = C.lbug_value_get_recursive_rel_rel_list(&v, &child)
			}
			if status != C.LbugSuccess {
				return fmt.Errorf("result budget: cannot read path")
			}
			err := b.check(child, depth+1)
			C.lbug_value_destroy(&child)
			if err != nil {
				return err
			}
		}
		return nil
	case C.LBUG_BOOL, C.LBUG_INT8, C.LBUG_INT16, C.LBUG_INT32, C.LBUG_INT64, C.LBUG_INT128, C.LBUG_SERIAL,
		C.LBUG_UINT8, C.LBUG_UINT16, C.LBUG_UINT32, C.LBUG_UINT64, C.LBUG_FLOAT, C.LBUG_DOUBLE, C.LBUG_DECIMAL,
		C.LBUG_UUID, C.LBUG_TIMESTAMP, C.LBUG_TIMESTAMP_NS, C.LBUG_TIMESTAMP_MS, C.LBUG_TIMESTAMP_SEC,
		C.LBUG_TIMESTAMP_TZ, C.LBUG_DATE, C.LBUG_INTERVAL, C.LBUG_INTERNAL_ID:
		return nil // Fixed-size scalars and bounded numeric/date representations.
	default:
		return fmt.Errorf("result budget: unsupported value type %d", kind)
	}
	if status != C.LbugSuccess {
		return fmt.Errorf("result budget: cannot read collection size")
	}
	if b.MaxCollectionItems <= 0 || uint64(size) > uint64(b.MaxCollectionItems) || uint64(size) > uint64(b.Values) {
		return ErrResultLimit
	}
	for i := C.uint64_t(0); i < size; i++ {
		var child C.lbug_value
		var name *C.char
		switch kind {
		case C.LBUG_LIST, C.LBUG_ARRAY:
			status = C.lbug_value_get_list_element(&v, i, &child)
		case C.LBUG_STRUCT, C.LBUG_UNION:
			if C.lbug_value_get_struct_field_name(&v, i, &name) != C.LbugSuccess {
				return fmt.Errorf("result budget: cannot read field name")
			}
			status = C.lbug_value_get_struct_field_value(&v, i, &child)
		case C.LBUG_NODE:
			if C.lbug_node_val_get_property_name_at(&v, i, &name) != C.LbugSuccess {
				return fmt.Errorf("result budget: cannot read property name")
			}
			status = C.lbug_node_val_get_property_value_at(&v, i, &child)
		case C.LBUG_REL:
			if C.lbug_rel_val_get_property_name_at(&v, i, &name) != C.LbugSuccess {
				return fmt.Errorf("result budget: cannot read property name")
			}
			status = C.lbug_rel_val_get_property_value_at(&v, i, &child)
		case C.LBUG_MAP:
			if C.lbug_value_get_map_key(&v, i, &child) != C.LbugSuccess {
				return fmt.Errorf("result budget: cannot read map key")
			}
			err := b.check(child, depth+1)
			C.lbug_value_destroy(&child)
			if err != nil {
				return err
			}
			status = C.lbug_value_get_map_value(&v, i, &child)
		}
		nameErr := b.text(name)
		if name != nil {
			C.lbug_destroy_string(name)
		}
		if status != C.LbugSuccess {
			return fmt.Errorf("result budget: cannot read collection element")
		}
		err := nameErr
		if err == nil {
			err = b.check(child, depth+1)
		}
		C.lbug_value_destroy(&child)
		if err != nil {
			return err
		}
	}
	return nil
}

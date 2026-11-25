package ladybug

// #include "lbug.h"
// #include <stdlib.h>
// #include <string.h>
import "C"

import (
	"fmt"
	"reflect"
	"sort"
	"time"
	"unsafe"

	"math/big"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// InternalID represents the internal ID of a node or relationship in Ladybug.
type InternalID struct {
	TableID uint64
	Offset  uint64
}

// Node represents a node retrieved from Ladybug.
// A node has an ID, a label, and properties.
type Node struct {
	ID         InternalID
	Label      string
	Properties map[string]any
}

// Relationship represents a relationship retrieved from Ladybug.
// A relationship has a source ID, a destination ID, a label, and properties.
type Relationship struct {
	ID            InternalID
	SourceID      InternalID
	DestinationID InternalID
	Label         string
	Properties    map[string]any
}

// RecursiveRelationship represents a recursive relationship retrieved from a
// path query in Ladybug. A recursive relationship has a list of nodes and a list
// of relationships.
type RecursiveRelationship struct {
	Nodes         []Node
	Relationships []Relationship
}

// MapItem represents a key-value pair in a map in Ladybug. It is used for both
// the query parameters and the query result.
type MapItem struct {
	Key   any
	Value any
}

// ladybugNodeValueToGoValue converts a ladybug_value representing a node to a Node
// struct in Go.
func ladybugNodeValueToGoValue(ladybugValue C.lbug_value) (Node, error) {
	node := Node{}
	node.Properties = make(map[string]any)
	idValue := C.lbug_value{}
	C.lbug_node_val_get_id_val(&ladybugValue, &idValue)
	nodeId, _ := ladybugValueToGoValue(idValue)
	node.ID = nodeId.(InternalID)
	C.lbug_value_destroy(&idValue)
	labelValue := C.lbug_value{}
	C.lbug_node_val_get_label_val(&ladybugValue, &labelValue)
	nodeLabel, _ := ladybugValueToGoValue(labelValue)
	node.Label = nodeLabel.(string)
	C.lbug_value_destroy(&labelValue)
	var propertySize C.uint64_t
	C.lbug_node_val_get_property_size(&ladybugValue, &propertySize)
	var currentKey *C.char
	var currentVal C.lbug_value
	var errors []error
	for i := C.uint64_t(0); i < propertySize; i++ {
		C.lbug_node_val_get_property_name_at(&ladybugValue, i, &currentKey)
		keyString := C.GoString(currentKey)
		C.lbug_destroy_string(currentKey)
		C.lbug_node_val_get_property_value_at(&ladybugValue, i, &currentVal)
		value, err := ladybugValueToGoValue(currentVal)
		if err != nil {
			errors = append(errors, err)
		}
		node.Properties[keyString] = value
		C.lbug_value_destroy(&currentVal)
	}
	if len(errors) > 0 {
		return node, fmt.Errorf("failed to get values: %v", errors)
	}
	return node, nil
}

// ladybugRelValueToGoValue converts a ladybug_value representing a relationship to a
// Relationship struct in Go.
func ladybugRelValueToGoValue(ladybugValue C.lbug_value) (Relationship, error) {
	relation := Relationship{}
	relation.Properties = make(map[string]any)
	idValue := C.lbug_value{}
	C.lbug_rel_val_get_id_val(&ladybugValue, &idValue)
	id, _ := ladybugValueToGoValue(idValue)
	relation.ID = id.(InternalID)
	C.lbug_value_destroy(&idValue)
	C.lbug_rel_val_get_src_id_val(&ladybugValue, &idValue)
	src, _ := ladybugValueToGoValue(idValue)
	relation.SourceID = src.(InternalID)
	C.lbug_value_destroy(&idValue)
	C.lbug_rel_val_get_dst_id_val(&ladybugValue, &idValue)
	dst, _ := ladybugValueToGoValue(idValue)
	relation.DestinationID = dst.(InternalID)
	C.lbug_value_destroy(&idValue)
	labelValue := C.lbug_value{}
	C.lbug_rel_val_get_label_val(&ladybugValue, &labelValue)
	label, _ := ladybugValueToGoValue(labelValue)
	relation.Label = label.(string)
	C.lbug_value_destroy(&labelValue)
	var propertySize C.uint64_t
	C.lbug_rel_val_get_property_size(&ladybugValue, &propertySize)
	var currentKey *C.char
	var currentVal C.lbug_value
	var errors []error
	for i := C.uint64_t(0); i < propertySize; i++ {
		C.lbug_rel_val_get_property_name_at(&ladybugValue, i, &currentKey)
		keyString := C.GoString(currentKey)
		C.lbug_destroy_string(currentKey)
		C.lbug_rel_val_get_property_value_at(&ladybugValue, i, &currentVal)
		value, err := ladybugValueToGoValue(currentVal)
		if err != nil {
			errors = append(errors, err)
		}
		relation.Properties[keyString] = value
		C.lbug_value_destroy(&currentVal)
	}
	if len(errors) > 0 {
		return relation, fmt.Errorf("failed to get values: %v", errors)
	}
	return relation, nil
}

// ladybugRecursiveRelValueToGoValue converts a ladybug_value representing a recursive
// relationship to a RecursiveRelationship struct in Go.
func ladybugRecursiveRelValueToGoValue(ladybugValue C.lbug_value) (RecursiveRelationship, error) {
	var nodesVal C.lbug_value
	var relsVal C.lbug_value
	C.lbug_value_get_recursive_rel_node_list(&ladybugValue, &nodesVal)
	C.lbug_value_get_recursive_rel_rel_list(&ladybugValue, &relsVal)
	defer C.lbug_value_destroy(&nodesVal)
	defer C.lbug_value_destroy(&relsVal)
	nodes, _ := ladybugListValueToGoValue(nodesVal)
	rels, _ := ladybugListValueToGoValue(relsVal)
	recursiveRel := RecursiveRelationship{}
	recursiveRel.Nodes = make([]Node, len(nodes))
	for i, n := range nodes {
		recursiveRel.Nodes[i] = n.(Node)
	}
	relationships := make([]Relationship, len(rels))
	for i, r := range rels {
		relationships[i] = r.(Relationship)
	}
	recursiveRel.Relationships = relationships
	return recursiveRel, nil
}

// ladybugListValueToGoValue converts a ladybug_value representing a LIST or ARRAY to
// a slice of any in Go.
func ladybugListValueToGoValue(ladybugValue C.lbug_value) ([]any, error) {
	var listSize C.uint64_t
	cLogicalType := C.lbug_logical_type{}
	defer C.lbug_data_type_destroy(&cLogicalType)
	C.lbug_value_get_data_type(&ladybugValue, &cLogicalType)
	logicalTypeId := C.lbug_data_type_get_id(&cLogicalType)
	if logicalTypeId == C.LBUG_ARRAY {
		C.lbug_data_type_get_num_elements_in_array(&cLogicalType, &listSize)
	} else {
		C.lbug_value_get_list_size(&ladybugValue, &listSize)
	}
	list := make([]any, 0, int(listSize))
	var currentVal C.lbug_value
	var errors []error
	for i := C.uint64_t(0); i < listSize; i++ {
		C.lbug_value_get_list_element(&ladybugValue, i, &currentVal)
		value, err := ladybugValueToGoValue(currentVal)
		if err != nil {
			errors = append(errors, err)
		}
		list = append(list, value)
		C.lbug_value_destroy(&currentVal)
	}
	if len(errors) > 0 {
		return list, fmt.Errorf("failed to get values: %v", errors)
	}
	return list, nil
}

// ladybugStructValueToGoValue converts a ladybug_value representing a STRUCT to a
// map of string to any in Go.
func ladybugStructValueToGoValue(ladybugValue C.lbug_value) (map[string]any, error) {
	structure := make(map[string]any)
	var propertySize C.uint64_t
	C.lbug_value_get_struct_num_fields(&ladybugValue, &propertySize)
	var currentKey *C.char
	var currentVal C.lbug_value
	var errors []error
	for i := C.uint64_t(0); i < propertySize; i++ {
		C.lbug_value_get_struct_field_name(&ladybugValue, i, &currentKey)
		keyString := C.GoString(currentKey)
		C.lbug_destroy_string(currentKey)
		C.lbug_value_get_struct_field_value(&ladybugValue, i, &currentVal)
		value, err := ladybugValueToGoValue(currentVal)
		if err != nil {
			errors = append(errors, err)
		}
		structure[keyString] = value
		C.lbug_value_destroy(&currentVal)
	}
	if len(errors) > 0 {
		return structure, fmt.Errorf("failed to get values: %v", errors)
	}
	return structure, nil
}

// ladybugMapValueToGoValue converts a ladybug_value representing a MAP to a
// slice of MapItem in Go.
func ladybugMapValueToGoValue(ladybugValue C.lbug_value) ([]MapItem, error) {
	var mapSize C.uint64_t
	C.lbug_value_get_map_size(&ladybugValue, &mapSize)
	mapItems := make([]MapItem, 0, int(mapSize))
	var currentKey C.lbug_value
	var currentValue C.lbug_value
	var errors []error
	for i := C.uint64_t(0); i < mapSize; i++ {
		C.lbug_value_get_map_key(&ladybugValue, i, &currentKey)
		C.lbug_value_get_map_value(&ladybugValue, i, &currentValue)
		key, err := ladybugValueToGoValue(currentKey)
		if err != nil {
			errors = append(errors, err)
		}
		value, err := ladybugValueToGoValue(currentValue)
		if err != nil {
			errors = append(errors, err)
		}
		C.lbug_value_destroy(&currentKey)
		C.lbug_value_destroy(&currentValue)
		mapItems = append(mapItems, MapItem{Key: key, Value: value})
	}
	if len(errors) > 0 {
		return mapItems, fmt.Errorf("failed to get values: %v", errors)
	}
	return mapItems, nil
}

// ladybugValueToGoValue converts a ladybug_value to a corresponding Go value.
func ladybugValueToGoValue(ladybugValue C.lbug_value) (any, error) {
	if C.lbug_value_is_null(&ladybugValue) {
		return nil, nil
	}
	var logicalType C.lbug_logical_type
	defer C.lbug_data_type_destroy(&logicalType)
	C.lbug_value_get_data_type(&ladybugValue, &logicalType)
	logicalTypeId := C.lbug_data_type_get_id(&logicalType)
	switch logicalTypeId {
	case C.LBUG_BOOL:
		var value C.bool
		status := C.lbug_value_get_bool(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get bool value with status: %d", status)
		}
		return bool(value), nil
	case C.LBUG_INT64, C.LBUG_SERIAL:
		var value C.int64_t
		status := C.lbug_value_get_int64(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get int64 value with status: %d", status)
		}
		return int64(value), nil
	case C.LBUG_INT32:
		var value C.int32_t
		status := C.lbug_value_get_int32(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get int32 value with status: %d", status)
		}
		return int32(value), nil
	case C.LBUG_INT16:
		var value C.int16_t
		status := C.lbug_value_get_int16(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get int16 value with status: %d", status)
		}
		return int16(value), nil
	case C.LBUG_INT128:
		var value C.lbug_int128_t
		status := C.lbug_value_get_int128(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get int128 value with status: %d", status)
		}
		return int128ToBigInt(value)
	case C.LBUG_INT8:
		var value C.int8_t
		status := C.lbug_value_get_int8(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get int8 value with status: %d", status)
		}
		return int8(value), nil
	case C.LBUG_UUID:
		var value *C.char
		status := C.lbug_value_get_uuid(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get uuid value with status: %d", status)
		}
		defer C.lbug_destroy_string(value)
		uuidString := C.GoString(value)
		return uuid.Parse(uuidString)
	case C.LBUG_UINT64:
		var value C.uint64_t
		status := C.lbug_value_get_uint64(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get uint64 value with status: %d", status)
		}
		return uint64(value), nil
	case C.LBUG_UINT32:
		var value C.uint32_t
		status := C.lbug_value_get_uint32(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get uint32 value with status: %d", status)
		}
		return uint32(value), nil
	case C.LBUG_UINT16:
		var value C.uint16_t
		status := C.lbug_value_get_uint16(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get uint16 value with status: %d", status)
		}
		return uint16(value), nil
	case C.LBUG_UINT8:
		var value C.uint8_t
		status := C.lbug_value_get_uint8(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get uint8 value with status: %d", status)
		}
		return uint8(value), nil
	case C.LBUG_DOUBLE:
		var value C.double
		status := C.lbug_value_get_double(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get double value with status: %d", status)
		}
		return float64(value), nil
	case C.LBUG_FLOAT:
		var value C.float
		status := C.lbug_value_get_float(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get float value with status: %d", status)
		}
		return float32(value), nil
	case C.LBUG_STRING:
		var outString *C.char
		status := C.lbug_value_get_string(&ladybugValue, &outString)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get string value with status: %d", status)
		}
		defer C.lbug_destroy_string(outString)
		return C.GoString(outString), nil
	case C.LBUG_TIMESTAMP:
		var value C.lbug_timestamp_t
		status := C.lbug_value_get_timestamp(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get timestamp value with status: %d", status)
		}
		return time.Unix(0, int64(value.value)*1000), nil
	case C.LBUG_TIMESTAMP_NS:
		var value C.lbug_timestamp_ns_t
		status := C.lbug_value_get_timestamp_ns(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get timestamp_ns value with status: %d", status)
		}
		return time.Unix(0, int64(value.value)), nil
	case C.LBUG_TIMESTAMP_MS:
		var value C.lbug_timestamp_ms_t
		status := C.lbug_value_get_timestamp_ms(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get timestamp_ms value with status: %d", status)
		}
		return time.Unix(0, int64(value.value)*1000000), nil
	case C.LBUG_TIMESTAMP_SEC:
		var value C.lbug_timestamp_sec_t
		status := C.lbug_value_get_timestamp_sec(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get timestamp_sec value with status: %d", status)
		}
		return time.Unix(int64(value.value), 0), nil
	case C.LBUG_TIMESTAMP_TZ:
		var value C.lbug_timestamp_tz_t
		status := C.lbug_value_get_timestamp_tz(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get timestamp_tz value with status: %d", status)
		}
		return time.Unix(0, int64(value.value)*1000), nil
	case C.LBUG_DATE:
		var value C.lbug_date_t
		status := C.lbug_value_get_date(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get date value with status: %d", status)
		}
		return ladybugDateToTime(value), nil
	case C.LBUG_INTERVAL:
		var value C.lbug_interval_t
		status := C.lbug_value_get_interval(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get interval value with status: %d", status)
		}
		return ladybugIntervalToDuration(value), nil
	case C.LBUG_INTERNAL_ID:
		var value C.lbug_internal_id_t
		status := C.lbug_value_get_internal_id(&ladybugValue, &value)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get internal_id value with status: %d", status)
		}
		return InternalID{TableID: uint64(value.table_id), Offset: uint64(value.offset)}, nil
	case C.LBUG_BLOB:
		var value *C.uint8_t
		var length C.uint64_t
		status := C.lbug_value_get_blob(&ladybugValue, &value, &length)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get blob value with status: %d", status)
		}
		defer C.lbug_destroy_blob(value)
		return C.GoBytes(unsafe.Pointer(value), C.int(length)), nil
	case C.LBUG_NODE:
		return ladybugNodeValueToGoValue(ladybugValue)
	case C.LBUG_REL:
		return ladybugRelValueToGoValue(ladybugValue)
	case C.LBUG_RECURSIVE_REL:
		return ladybugRecursiveRelValueToGoValue(ladybugValue)
	case C.LBUG_LIST, C.LBUG_ARRAY:
		return ladybugListValueToGoValue(ladybugValue)
	case C.LBUG_STRUCT, C.LBUG_UNION:
		return ladybugStructValueToGoValue(ladybugValue)
	case C.LBUG_MAP:
		return ladybugMapValueToGoValue(ladybugValue)
	case C.LBUG_DECIMAL:
		var outString *C.char
		status := C.lbug_value_get_decimal_as_string(&ladybugValue, &outString)
		if status != C.LbugSuccess {
			return nil, fmt.Errorf("failed to get string value of decimal type with status: %d", status)
		}
		goString := C.GoString(outString)
		C.lbug_destroy_string(outString)
		goDecimal, casting_error := decimal.NewFromString(goString)
		if casting_error != nil {
			return nil, fmt.Errorf("failed to convert decimal value with error: %w", casting_error)
		}
		return goDecimal, casting_error
	default:
		valueString := C.lbug_value_to_string(&ladybugValue)
		defer C.lbug_destroy_string(valueString)
		return C.GoString(valueString), fmt.Errorf("unsupported data type with type id: %d. the value is force-casted to string", logicalTypeId)
	}
}

// int128ToBigInt converts a ladybug_int128_t to a big.Int in Go.
func int128ToBigInt(value C.lbug_int128_t) (*big.Int, error) {
	var outString *C.char
	status := C.lbug_int128_t_to_string(value, &outString)
	if status != C.LbugSuccess {
		return nil, fmt.Errorf("failed to convert int128 to string with status: %d", status)
	}
	defer C.lbug_destroy_string(outString)
	valueString := C.GoString(outString)
	bigInt := new(big.Int)
	_, success := bigInt.SetString(valueString, 10)
	if !success {
		return nil, fmt.Errorf("failed to convert string to big.Int")
	}
	return bigInt, nil
}

// goMapToLadybugStruct converts a map of string to any to a ladybug_value representing
// a STRUCT. It returns an error if the map is empty.
func goMapToLadybugStruct(value map[string]any) (*C.lbug_value, error) {
	numFields := C.uint64_t(len(value))
	if numFields == 0 {
		return nil, fmt.Errorf("failed to create STRUCT value because the map is empty")
	}
	fieldNames := make([]*C.char, 0, len(value))
	fieldValues := make([]*C.lbug_value, 0, len(value))
	// Sort the keys to ensure the order is consistent.
	// This is useful for creating a LIST of STRUCTs because in Ladybug, all the
	// LIST elements must have the same type (i.e., the same order of fields).
	sortedKeys := make([]string, 0, len(value))
	for k := range value {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, k := range sortedKeys {
		// Capture the CString once: free the exact pointer stored in fieldNames,
		// not a second freshly-allocated copy (`C.free(C.CString(k))` would free
		// a throwaway allocation and leak the one passed to create_struct).
		// ladybug_value_create_struct copies the names, so freeing them on return is
		// safe.
		cName := C.CString(k)
		fieldNames = append(fieldNames, cName)
		ladybugValue, err := goValueToLadybugValue(value[k])
		if err != nil {
			C.free(unsafe.Pointer(cName))
			return nil, fmt.Errorf("failed to convert value in the map with error: %w", err)
		}
		fieldValues = append(fieldValues, ladybugValue)
		defer C.lbug_value_destroy(ladybugValue)
		defer C.free(unsafe.Pointer(cName))
	}

	var ladybugValue *C.lbug_value
	status := C.lbug_value_create_struct(numFields, &fieldNames[0], &fieldValues[0], &ladybugValue)
	if status != C.LbugSuccess {
		return nil, fmt.Errorf("failed to create STRUCT value with status: %d", status)
	}
	return ladybugValue, nil
}

// goSliceOfMapItemsToLadybugMap converts a slice of MapItem to a ladybug_value
// representing a MAP. It returns an error if the slice is empty or if the keys
// in the slice are of different types or if the values in the slice are of
// different types.
func goSliceOfMapItemsToLadybugMap(slice []MapItem) (*C.lbug_value, error) {
	numItems := C.uint64_t(len(slice))
	if numItems == 0 {
		return nil, fmt.Errorf("failed to create MAP value because the slice is empty")
	}
	keys := make([]*C.lbug_value, 0, len(slice))
	values := make([]*C.lbug_value, 0, len(slice))
	for _, item := range slice {
		key, error := goValueToLadybugValue(item.Key)
		if error != nil {
			return nil, fmt.Errorf("failed to convert key in the slice with error: %w", error)
		}
		keys = append(keys, key)
		defer C.lbug_value_destroy(key)
		value, error := goValueToLadybugValue(item.Value)
		if error != nil {
			return nil, fmt.Errorf("failed to convert value in the slice with error: %w", error)
		}
		values = append(values, value)
		defer C.lbug_value_destroy(value)
	}
	var ladybugValue *C.lbug_value
	status := C.lbug_value_create_map(numItems, &keys[0], &values[0], &ladybugValue)
	if status != C.LbugSuccess {
		return nil, fmt.Errorf("failed to create MAP value with status: %d. please make sure all the keys are of the same type and all the values are of the same type", status)
	}
	return ladybugValue, nil
}

// goSliceToLadybugList converts a slice of any to a ladybug_value representing a LIST.
// It returns an error if the slice is empty or if the values in the slice are of
// different types.
func goSliceToLadybugList(slice []any) (*C.lbug_value, error) {
	numItems := C.uint64_t(len(slice))
	if numItems == 0 {
		return nil, fmt.Errorf("failed to create LIST value because the slice is empty")
	}
	values := make([]*C.lbug_value, 0, len(slice))
	for _, item := range slice {
		value, error := goValueToLadybugValue(item)
		if error != nil {
			return nil, fmt.Errorf("failed to convert value in the slice with error: %w", error)
		}
		values = append(values, value)
		defer C.lbug_value_destroy(value)
	}
	var ladybugValue *C.lbug_value
	status := C.lbug_value_create_list(numItems, &values[0], &ladybugValue)
	if status != C.LbugSuccess {
		return nil, fmt.Errorf("failed to create LIST value with status: %d. please make sure all the values are of the same type", status)
	}
	return ladybugValue, nil
}

// goValueToLadybugValue converts a Go value to a ladybug_value.
func goValueToLadybugValue(value any) (*C.lbug_value, error) {
	if value == nil {
		return C.lbug_value_create_null(), nil
	}
	var ladybugValue *C.lbug_value
	switch v := value.(type) {
	case bool:
		ladybugValue = C.lbug_value_create_bool(C.bool(v))
	case int:
		ladybugValue = C.lbug_value_create_int64(C.int64_t(v))
	case int64:
		ladybugValue = C.lbug_value_create_int64(C.int64_t(v))
	case int32:
		ladybugValue = C.lbug_value_create_int32(C.int32_t(v))
	case int16:
		ladybugValue = C.lbug_value_create_int16(C.int16_t(v))
	case int8:
		ladybugValue = C.lbug_value_create_int8(C.int8_t(v))
	case uint:
		ladybugValue = C.lbug_value_create_uint64(C.uint64_t(v))
	case uint64:
		ladybugValue = C.lbug_value_create_uint64(C.uint64_t(v))
	case uint32:
		ladybugValue = C.lbug_value_create_uint32(C.uint32_t(v))
	case uint16:
		ladybugValue = C.lbug_value_create_uint16(C.uint16_t(v))
	case uint8:
		ladybugValue = C.lbug_value_create_uint8(C.uint8_t(v))
	case float64:
		ladybugValue = C.lbug_value_create_double(C.double(v))
	case float32:
		ladybugValue = C.lbug_value_create_float(C.float(v))
	case string:
		// ladybug_value_create_string takes a const char* and copies it, so the
		// CString must be freed here — otherwise every string parameter bind
		// (i.e. nearly every query) leaks the heap allocation.
		cs := C.CString(v)
		ladybugValue = C.lbug_value_create_string(cs)
		C.free(unsafe.Pointer(cs))
	case time.Time:
		if timeHasNanoseconds(v) {
			ladybugValue = C.lbug_value_create_timestamp_ns(timeToLadybugTimestampNs(v))
		} else {
			ladybugValue = C.lbug_value_create_timestamp(timeToLadybugTimestamp(v))
		}
	case time.Duration:
		interval := durationToLadybugInterval(v)
		ladybugValue = C.lbug_value_create_interval(interval)
	case map[string]any:
		return goMapToLadybugStruct(v)
	case []MapItem:
		return goSliceOfMapItemsToLadybugMap(v)
	case []any:
		return goSliceToLadybugList(v)
	default:
		if reflect.TypeOf(value).Kind() == reflect.Slice {
			sliceValue := reflect.ValueOf(value)
			slice := make([]any, sliceValue.Len())
			for i := 0; i < sliceValue.Len(); i++ {
				slice[i] = sliceValue.Index(i).Interface()
			}
			return goSliceToLadybugList(slice)
		}
		return nil, fmt.Errorf("unsupported type: %T", v)
	}
	return ladybugValue, nil
}

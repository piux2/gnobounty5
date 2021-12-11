// Code generated by "stringer -type=Kind"; DO NOT EDIT.

package gno

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[InvalidKind-0]
	_ = x[BoolKind-1]
	_ = x[StringKind-2]
	_ = x[IntKind-3]
	_ = x[Int8Kind-4]
	_ = x[Int16Kind-5]
	_ = x[Int32Kind-6]
	_ = x[Int64Kind-7]
	_ = x[UintKind-8]
	_ = x[Uint8Kind-9]
	_ = x[Uint16Kind-10]
	_ = x[Uint32Kind-11]
	_ = x[Uint64Kind-12]
	_ = x[BigintKind-13]
	_ = x[ArrayKind-14]
	_ = x[SliceKind-15]
	_ = x[PointerKind-16]
	_ = x[StructKind-17]
	_ = x[PackageKind-18]
	_ = x[InterfaceKind-19]
	_ = x[ChanKind-20]
	_ = x[FuncKind-21]
	_ = x[MapKind-22]
	_ = x[TypeKind-23]
	_ = x[BlockKind-24]
	_ = x[TupleKind-25]
	_ = x[RefTypeKind-26]
}

const _Kind_name = "InvalidKindBoolKindStringKindIntKindInt8KindInt16KindInt32KindInt64KindUintKindUint8KindUint16KindUint32KindUint64KindBigintKindArrayKindSliceKindPointerKindStructKindPackageKindInterfaceKindChanKindFuncKindMapKindTypeKindBlockKindTupleKindRefTypeKind"

var _Kind_index = [...]uint8{0, 11, 19, 29, 36, 44, 53, 62, 71, 79, 88, 98, 108, 118, 128, 137, 146, 157, 167, 178, 191, 199, 207, 214, 222, 231, 240, 251}

func (i Kind) String() string {
	if i >= Kind(len(_Kind_index)-1) {
		return "Kind(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Kind_name[_Kind_index[i]:_Kind_index[i+1]]
}

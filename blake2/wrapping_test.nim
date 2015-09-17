import unsigned

type
  NotU64 = int|int8|int16|int32|int64|uint8|uint16|uint32

proc `mod`[T: SomeSignedInt, U: SomeUnsignedInt](x: T, y: U): T {.magic: "ModU", noSideEffect.}
proc `+`[T: SomeSignedInt, U: SomeUnsignedInt](x: T, y: U): T {.magic: "AddU", noSideEffect.}
proc `-`[T: SomeSignedInt, U: SomeUnsignedInt](x: T, y: U): T {.magic: "SubU", noSideEffect.}

proc wrappingAdd[T: NotU64](itype: T, n: Natural): T =
  var res = itype.uint64 + n.uint64
  if res > uint64(high(T)):
    result = ((res - high(T).uint64 - 1).uint64 - high(T).uint64 - 1).T
  else:
    result = res.T

proc wrappingAdd[T: uint64](itype: T, n: Natural): T =
  # this just lets it overflow, which it seems to do automatically
  # but may be platform-specific
  result = itype + n.T # if it's greater that the highest uint64,
                 # we can't handle it anyways

proc wrappingSub[T: NotU64](itype: T, n: Natural): T =
  result = -wrappingAdd(itype, n)

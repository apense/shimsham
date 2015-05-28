import strutils

type Foo = object

proc initFoo(): Foo =
  discard

proc process*(f: var Foo, message: openarray[byte]) =
  discard

proc process*(f: var Foo, message: string) =
  ## do stuff
  assert(len(message) mod 2 == 0)

var f: Foo = initFoo()
f.process("hellos")
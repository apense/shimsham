
type
  RandomNumberGenerator* = ref RandomNumberGeneratorObj
  RandomNumberGeneratorObj* = object {.inheritable.}
    next*: proc(numBits: int): int

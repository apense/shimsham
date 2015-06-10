import unsigned

const
  Key* = 0
  Config* = 4
  Personalization* = 8
  PublicKey* = 12
  KeyIdentifier* = 16
  Nonce* = 20
  Message* = 48
  Out* = 63

const
  T1FlagFinal = 1'u64 shl 63
  T1FlagFirst = 1'u64 shl 62
  T1FlagBitPad = 1'u64 shl 55

type
  UbiTweak* = object
    tweak: array[2, uint64]

proc initUbiTweak*(): UbiTweak =
  discard

proc isFirstBlock(u: UbiTweak): bool =
  ## Get status of the first block flag
  result = (u.tweak[1] and T1FlagFirst) != 0

proc setFirstBlock*(u: var UbiTweak, value: bool) =
  ## Sets status of the first block flag
  if value:
    u.tweak[1] = u.tweak[1] or T1FlagFirst
  else:
    u.tweak[1] = u.tweak[1] and not T1FlagFirst

proc isFinalBlock(u: UbiTweak): bool =
  ## Gets status of the final block flag
  result = (u.tweak[1] and T1FlagFinal) != 0

proc setFinalBlock*(u: var UbiTweak, value: bool) =
  ## Sets status of the final block flag
  if value:
    u.tweak[1] = u.tweak[1] or T1FlagFinal
  else:
    u.tweak[1] = u.tweak[1] and not T1FlagFinal

proc isBitPad*(u: UbiTweak): bool =
  ## Gets status of the final block flag
  result = (u.tweak[1] and T1FlagBitPad) != 0

proc setBitPad*(u: var UbiTweak, value: bool) =
  if value:
    u.tweak[1] = u.tweak[1] or T1FlagBitPad
  else:
    u.tweak[1] = u.tweak[1] and not T1FlagBitPad

proc getTreeLevel(u: UbiTweak): byte =
  ## Gets the current tree level
  result = byte((u.tweak[1] shr 48) and 0x7f)

proc setTreeLevel(u: var UbiTweak, value: int) =
  ## Set the current tree level
  u.tweak[1] = u.tweak[1] and not (0x7f'u64 shl 48)
  u.tweak[1] = u.tweak[1] or (value.uint64 shl 48)

proc getBitsProcessed*(u: UbiTweak): tuple[lo, hi: uint64] =
  ## Gets the number of bytes processed so far, inclusive
  result.lo = u.tweak[0]
  result.hi = u.tweak[1] and 0xffffffff

proc setBitsProcessed*(u: var UbiTweak, value: uint64) =
  ## Set the number of bytes processed so far
  u.tweak[0] = value
  u.tweak[1] = u.tweak[1] and 0xffffffff00000000'u64

proc addBytesProcessed*(u: var UbiTweak, value: int) =
  ## Adds `value` to 96-bit field of processed bytes
  const length = 3
  var carry = value.uint64

  var words: array[length, uint64]

  words[0] = u.tweak[0] and 0xffffffff
  words[1] = (u.tweak[0] shr 32) and 0xffffffff
  words[2] = u.tweak[1] and 0xffffffff

  for i in 0..<length:
    carry += words[i]
    words[i] = carry
    carry = carry shr 32

  u.tweak[0] = words[0] and 0xffffffff
  u.tweak[0] = u.tweak[0] or ((words[1] and 0xffffffff) shl 32)
  u.tweak[1] = u.tweak[1] or (words[2] and 0xffffffff)

proc getBlockType(u: UbiTweak): uint64 =
  ## Get the current UBI block type
  result = (u.tweak[1] shr 56) and 0x3f

proc setBlockType(u: var UbiTweak, value: uint64) =
  ## Set the current UBI block type
  u.tweak[1] = value shl 56

proc startNewBlockType*(u: var UbiTweak, t: uint64) =
  ## Starts a new UBI block type by setting BitsProcessed to zero,
  ## setting the first flag, and setting the block type
  u.setBitsProcessed(0)
  u.setBlockType(t)
  u.setFirstBlock(true)

proc getTweak*(u: UbiTweak): array[2, uint64] =
  result = u.tweak

proc setTweak(u: var UbiTweak, tw: openarray[uint64]) =
  u.tweak[0] = tw[0]
  u.tweak[1] = tw[1]

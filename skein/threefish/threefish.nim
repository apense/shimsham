import unsigned
export unsigned

include util

const
  KeyScheduleConst* = 0x1bd11bdaa9fc1a22'u64
  ExpandedTweakSize* = 3

type
  Cipher* = ref CipherInternal
  CipherInternal* = object of RootObj
    encryptImpl*: proc (c: Cipher, input: openarray[uint64],
      output: var openarray[uint64]) {.nimcall.}
    decryptImpl*: proc (c: Cipher, input: openarray[uint64],
      output: var openarray[uint64]) {.nimcall.}
    getTempDataImpl*: proc (c: Cipher): tuple[a, b: seq[uint64]] {.nimcall.}
    setTweakImpl*: proc (c: Cipher, tweak: openarray[uint64]) {.nimcall.}
    setKeyImpl*: proc (c: Cipher, key: openarray[uint64]) {.nimcall.}
    stateSize*: int

type
  KeySizeError* = int

proc raiseKeySizeError*(k: KeySizeError) {.raises: [ValueError].} =
  raise newException(ValueError, "threefish: invalid key size " & $k)

proc blocksize*(c: Cipher): int {.noSideEffect.} =
  result = c.stateSize div 8

proc setTweak*(tweak: openarray[uint64],
  expandedTweak: var openarray[uint64]) {.noSideEffect.} =
  if tweak.len > 0:
    expandedTweak[0] = tweak[0]
    expandedTweak[1] = tweak[1]
    expandedTweak[2] = tweak[0] xor tweak[1]

proc setKey*(key: openarray[uint64],
  expandedKey: var openarray[uint64]) {.noSideEffect.} =
  var parity = KeyScheduleConst.uint64

  var i: int
  while i < expandedKey.len-1:
    expandedKey[i] = key[i]
    parity = parity xor key[i]
    inc i

  expandedKey[i] = parity

import threefish256
import threefish512
import threefish1024

proc newTweak*(key: openarray[byte], tweak: openarray[uint64]): Cipher =
  case key.len
  of 32:
    result = newThreefish256(key, tweak)
  of 64:
    result = newThreefish512(key, tweak)
  of 128:
    result = newThreefish1024(key, tweak)
  else:
    raiseKeySizeError(key.len)
  result.stateSize = len(key) * 8

proc newTweak*(key, tweak: openarray[uint64]): Cipher =
  case key.len
  of 4:
    result = newThreefish256(key, tweak)
  of 8:
    result = newThreefish512(key, tweak)
  of 16:
    result = newThreefish1024(key, tweak)
  else:
    raiseKeySizeError(len(key))
  result.stateSize = len(key) * 8

proc newSize*(size: int): Cipher =
  var newb = newSeq[byte]()
  var newu = newSeq[uint64]()
  case size
  of 256:
    result = newThreefish256(newb,newu)
  of 512:
    result = newThreefish512(newb,newu)
  of 1024:
    result = newThreefish1024(newb,newu)
  else:
    raiseKeySizeError(size)
  result.stateSize = size

proc encrypt*(c: Cipher, dst: var openarray[byte], src: openarray[byte]) =
  var uintLen = c.stateSize div 64
  var (tmpin, tmpout) = c.getTempDataImpl(c)

  for i in 0..<uintLen:
    tmpin[i] = uint64le(src, i*8)

  c.encryptImpl(c,tmpin, tmpout)

  for i in 0..<uintLen:
    putUint64le(dst, i*8, tmpout[i])

proc encrypt*(c: Cipher, dst: var openarray[uint64], src: openarray[uint64]) =
  c.encryptImpl(c, src, dst)

proc decrypt*(c: Cipher, dst: var openarray[byte], src: openarray[byte]) =
  var uintLen = c.stateSize div 64
  var (tmpin, tmpout) = c.getTempDataImpl(c)

  for i in 0..<uintLen:
    tmpin[i] = uint64le(src, i*8)

  c.decryptImpl(c,tmpin,tmpout)

  for i in 0..<uintLen:
    putUint64le(dst, i*8, tmpout[i])

proc decrypt*(c: Cipher, dst: var openarray[uint64], src: openarray[uint64]) =
  c.decryptImpl(c, src, dst)

proc setKey*(c: Cipher, key: openarray[uint64]) =
  c.setKeyImpl(c, key)

proc setTweak*(c: Cipher, tweak: openarray[uint64]) =
  c.setTweakImpl(c, tweak)

when isMainModule:
  let key256 = @[0x1716151413121110'u64,0x1F1E1D1C1B1A1918'u64,0x2726252423222120'u64, 0x2F2E2D2C2B2A2928'u64]
  let input256 = @[0xF8F9FAFBFCFDFEFF'u64,0xF0F1F2F3F4F5F6F7'u64,0xE8E9EAEBECEDEEEF'u64, 0xE0E1E2E3E4E5E6E7'u64]
  let tweak256 = @[0x0706050403020100'u64,0x0F0E0D0C0B0A0908'u64]
  let result256 = @[0x277610F5036C2E1F'u64, 0x25FB2ADD1267773E'u64,
      0x9E1D67B3E4B06872'u64, 0x3F76BC7651B39682'u64]

  var key = newSeq[byte](256 div 8)
  var dataIn = newSeq[byte](256 div 8)
  var dataOut = newSeq[byte](256 div 8)
  var result = newSeq[byte](256 div 8)

  for i in 0..<len(input256):
    putUint64le(dataIn, i*8, input256[i])
    putUint64le(key, i*8, key256[i])
    putUint64le(result, i*8, result256[i])

  var cipher = newThreefish256(key, tweak256)
  cipher.encrypt(dataOut, dataIn)
  # plaintext feed forward
  for i in 0..<len(dataIn):
    dataOut[i] = dataOut[i] xor dataIn[i]
  assert (dataOut == result)

  # plaintext feed backward
  for i in 0..<len(dataIn):
    dataOut[i] = dataOut[i] xor dataIn[i]

  cipher.decrypt(result, dataOut)
  assert (dataIn == result)

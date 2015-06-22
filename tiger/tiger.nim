import sboxes
import strutils
import unsigned

# TODO
# Somewhere in this code, the bytes in the output got swapped somehow
# I need to go back through and fix it
# It's tempting to change `doFinal` with the offsets, but that's cheap
# and wrong

type
  TigerDigest* = object
    a,b,c: uint64
    byteCount: int
    buf: seq[byte]
    bOff: int
    x: seq[uint64]
    xOff: int

proc reset*(t: var TigerDigest) =
  t.a = 0x0123456789abcdef'u64
  t.b = 0xfedcba9876543210'u64
  t.c = 0xf096a5b4c3b2e187'u64
  t.xOff = 0
  for i in 0..<8:
    t.x[i] = 0.uint64
  t.bOff = 0
  for i in 0..<8:
    t.buf[i] = 0.byte
  t.byteCount = 0

proc initTigerDigest*(): TigerDigest =
  result.buf = newSeq[byte](8)
  result.x = newSeq[uint64](8)
  result.bOff = 0
  result.xOff = 0
  result.reset()

proc roundABC(t: var TigerDigest, x, mul: uint64) =
  t.c = t.c xor x.uint64
  t.a -= Table1[t.c.int and 0xff].uint64 xor Table2[(t.c shr 16).int and 0xff].uint64 xor
         Table3[(t.c shr 32).int and 0xff].uint64 xor Table4[(t.c shr 48).int and 0xff].uint64
  t.b += Table4[(t.c shr 8).int and 0xff].uint64 xor Table3[(t.c shr 24).int and 0xff].uint64 xor
         Table2[(t.c shr 40).int and 0xff].uint64 xor Table1[(t.c shr 56).int and 0xff].uint64
  t.b *= mul.uint64

proc roundBCA(t: var TigerDigest, x, mul: uint64) =
  t.a = t.a xor x
  t.b -= Table1[t.a.int and 0xff].uint64 xor Table2[(t.a shr 16).int and 0xff].uint64 xor
         Table3[(t.a shr 32).int and 0xff].uint64 xor Table4[(t.a shr 48).int and 0xff].uint64
  t.c += Table4[(t.a shr 8).int and 0xff].uint64 xor Table3[(t.a shr 24).int and 0xff].uint64 xor
         Table2[(t.a shr 40).int and 0xff].uint64 xor Table1[(t.a shr 56).int and 0xff].uint64
  t.c *= mul

proc roundCAB(t: var TigerDigest, x, mul: uint64) =
  t.b = t.b xor x
  t.c -= Table1[t.b.int and 0xff].uint64 xor Table2[(t.b shr 16).int and 0xff].uint64 xor
         Table3[(t.b shr 32).int and 0xff].uint64 xor Table4[(t.b shr 48).int and 0xff].uint64
  t.a += Table4[(t.b shr 8).int and 0xff].uint64 xor Table3[(t.b shr 24).int and 0xff].uint64 xor
         Table2[(t.b shr 40).int and 0xff].uint64 xor Table1[(t.b shr 56).int and 0xff].uint64
  t.a *= mul

proc keySchedule(t: var TigerDigest) =
  t.x[0] -= t.x[7] xor 0xa5a5a5a5a5a5a5a5'u64
  t.x[1] = t.x[1] xor t.x[0]
  t.x[2] += t.x[1]
  t.x[3] -= t.x[2] xor (not(t.x[1]) shl 19)
  t.x[4] = t.x[4] xor t.x[3]
  t.x[5] += t.x[4]
  t.x[6] -= t.x[5] xor (not(t.x[4]) shr 23)
  t.x[7] = t.x[7] xor t.x[6]
  t.x[0] += t.x[7]
  t.x[1] -= t.x[0] xor (not(t.x[7]) shl 19)
  t.x[2] = t.x[2] xor t.x[1]
  t.x[3] += t.x[2]
  t.x[4] -= t.x[3] xor (not(t.x[2]) shr 23)
  t.x[5] = t.x[5] xor t.x[4]
  t.x[6] += t.x[5]
  t.x[7] -= t.x[6] xor 0x0123456789abcdef

proc processBlock(t: var TigerDigest) =
  # save a,b,c
  var (aa,bb,cc) = (t.a,t.b,t.c)

  # rounds and schedule
  t.roundABC(t.x[0], 5)
  t.roundBCA(t.x[1], 5)
  t.roundCAB(t.x[2], 5)
  t.roundABC(t.x[3], 5)
  t.roundBCA(t.x[4], 5)
  t.roundCAB(t.x[5], 5)
  t.roundABC(t.x[6], 5)
  t.roundBCA(t.x[7], 5)

  t.keySchedule()

  t.roundCAB(t.x[0], 7)
  t.roundABC(t.x[1], 7)
  t.roundBCA(t.x[2], 7)
  t.roundCAB(t.x[3], 7)
  t.roundABC(t.x[4], 7)
  t.roundBCA(t.x[5], 7)
  t.roundCAB(t.x[6], 7)
  t.roundABC(t.x[7], 7)

  t.keySchedule()

  t.roundBCA(t.x[0], 9)
  t.roundCAB(t.x[1], 9)
  t.roundABC(t.x[2], 9)
  t.roundBCA(t.x[3], 9)
  t.roundCAB(t.x[4], 9)
  t.roundABC(t.x[5], 9)
  t.roundBCA(t.x[6], 9)
  t.roundCAB(t.x[7], 9)

  # feed forward
  t.a = t.a xor aa
  t.b -= bb
  t.c += cc

  # clear the x buffer
  t.xOff = 0
  for i in 0..<8:
    t.x[i] = 0.uint64

proc processWord(t: var TigerDigest, b: seq[byte], off: int) =
  #echo "len t.x: ", len(t.x)
  #echo "t.xOff: ", t.xOff
  t.x[t.xOff] = ((b[off + 7] and 0xff) shl 56).uint64 or
                ((b[off + 6] and 0xff) shl 48).uint64 or
                ((b[off + 5] and 0xff) shl 40).uint64 or
                ((b[off + 4] and 0xff) shl 32).uint64 or
                ((b[off + 3] and 0xff) shl 24).uint64 or
                ((b[off + 2] and 0xff) shl 16).uint64 or
                ((b[off + 1] and 0xff) shl  8).uint64 or
                ((b[off + 0])).uint64
  inc(t.xOff)

  if(t.xOff == t.x.len):
    t.processBlock()

  t.bOff = 0

proc unpackWord(r: int, outbytes: var seq[byte], outOff: int) {.noSideEffect.} =
  outbytes[outOff + 7] = (r shr 56).byte
  outbytes[outOff + 6] = (r shr 48).byte
  outbytes[outOff + 5] = (r shr 40).byte
  outbytes[outOff + 4] = (r shr 32).byte
  outbytes[outOff + 3] = (r shr 24).byte
  outbytes[outOff + 2] = (r shr 16).byte
  outbytes[outOff + 1] = (r shr  8).byte
  outbytes[outOff + 0] = (r).byte

proc processLength(t: var TigerDigest, bitLength: int) =
  t.x[7] = bitLength.uint64

proc update*(t: var TigerDigest, inbyte: byte) =
  t.buf[t.bOff] = inbyte
  inc(t.bOff)

  if(t.bOff == t.buf.len):
    t.processWord(t.buf, 0)

  inc t.byteCount

proc update(t: var TigerDigest, inbytes: var seq[byte], inOff, length: int) =
  # fill the current word
  var (myInOff, myLen) = (inOff, length)
  while((t.bOff != 0) and (myLen > 0)):
    t.update(inbytes[myInOff])
    inc myInOff
    dec myLen

  # process whole words
  while(myLen > 8):
    t.processWord(inbytes, myInOff)

    myInOff += 8
    myLen -= 8
    t.byteCount += 8

  # load in the remainder
  while(myLen > 0):
    t.update(inbytes[myInOff])
    inc myInOff
    dec myLen

proc finish(t: var TigerDigest) =
  var bitLength = (t.byteCount shl 3)

  t.update(0x01.byte)

  while(t.bOff != 0):
    t.update(0.byte)

  t.processLength(bitLength)

  t.processBlock()

proc doFinal(t: var TigerDigest, outbytes: var seq[byte], outOff: int) =
  t.finish()

  unpackWord(t.a.int, outbytes, outOff)
  unpackWord(t.b.int, outbytes, outOff + 8)
  unpackWord(t.c.int, outbytes, outOff + 16)

  t.reset()


proc getBytes(s: string): seq[byte] {.noSideEffect.} =
  var i = s.len
  var abyte0 = newSeq[byte](i)
  var j = 0

  while(j < i):
    abyte0[j] = s[j].byte
    inc j

  result = abyte0

proc tigerBytes*(s: string = nil): seq[byte] =
  var m = initTigerDigest()
  var message = s.getBytes()
  m.update(message, 0, message.len)
  result = newSeq[byte](DigestLength)
  m.doFinal(result,0)
  var (tmp0, tmp1, tmp2) = (result[16..23], result[8..15], result[0..7])
  result = tmp0 & tmp1 & tmp2

proc tigerBytes*(s: seq[byte]): seq[byte] =
  var m = initTigerDigest()
  var message = s
  m.update(message, 0, message.len)
  result = newSeq[byte](DigestLength)
  m.doFinal(result,0)
  var (tmp0, tmp1, tmp2) = (result[16..23], result[8..15], result[0..7])
  result = tmp0 & tmp1 & tmp2

proc tiger*(s: string = nil): string =
  var res: seq[byte] = tigerBytes(s)
  result = ""
  for i in res:
    result = toHex(i.int, 2).toLower() & result

proc tiger*(s: seq[byte]): string =
  var res: seq[byte] = tigerBytes(s)
  result = ""
  for i in res:
    result = toHex(i.int, 2).toLower() & result


when isMainModule:
  assert(tiger("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01" &
        "23456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345" &
        "6789+-") == "00b83eb4e53440c576ac6aaee0a7485825fd15e70a59ffe4")
  assert(tiger("") == "24f0130c63ac933216166e76b1bb925ff373de2d49584e7a")

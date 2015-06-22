## Based off the Rust implementation at
## <https://github.com/dgryski/siphash-rust>_

import unsigned
import strutils

type
  SipState* = object ## represents a Sip Hash
    k0,k1: uint64
    length: int ## how many bytes we've processed
    v0,v1,v2,v3: uint64 ## state
    tail: array[8,byte] ## unprocessed bytes
    ntail: int ## valid bytes in tail

proc rotl(x: uint64, b: uint): uint64 {.inline, noSideEffect.} =
  result = (x shl b) or (x shr (64'u64 - b))

proc loadu64(b: openarray[byte], i: int): uint64 {.inline, noSideEffect.} =
  result = (b[0+i].uint64 shl  0) or
           (b[1+i].uint64 shl  8) or
           (b[2+i].uint64 shl 16) or
           (b[3+i].uint64 shl 24) or
           (b[4+i].uint64 shl 32) or
           (b[5+i].uint64 shl 40) or
           (b[6+i].uint64 shl 48) or
           (b[7+i].uint64 shl 56)

proc sipround(v0, v1, v2, v3: var uint64) {.inline, noSideEffect.} =
  v0 = v0 + v1; v1 = rotl(v1, 13); v1 = v1 xor v0; v0 = rotl(v0, 32)
  v2 = v2 + v3; v3 = rotl(v3, 16); v3 = v3 xor v2
  v0 = v0 + v3; v3 = rotl(v3, 21); v3 = v3 xor v0
  v2 = v2 + v1; v1 = rotl(v1, 17); v1 = v1 xor v2; v2 = rotl(v2, 32)

proc addInput(st: var SipState, msg: openarray[byte]) =
  let length = len(msg)
  st.length += length
  var needed = 0

  if st.ntail != 0:
    needed = 8 - st.ntail
    if length < needed:
      var t = 0
      while t < length:
        st.tail[st.ntail+t] = msg[t] ## populate unprocessed bytes
        inc t
      st.ntail += length

      return

    var t = 0
    while t < needed:
      st.tail[st.ntail+t] = msg[t]
      inc t
    st.ntail += needed
    # grab a little-endian uint64 from st.tail
    let m = (st.tail[0].uint64 shl  0) or
            (st.tail[1].uint64 shl  8) or
            (st.tail[2].uint64 shl 16) or
            (st.tail[3].uint64 shl 24) or
            (st.tail[4].uint64 shl 32) or
            (st.tail[5].uint64 shl 40) or
            (st.tail[6].uint64 shl 48) or
            (st.tail[7].uint64 shl 56)
    st.v3 = st.v3 xor m
    sipround(st.v0, st.v1, st.v2, st.v3)
    sipround(st.v0, st.v1, st.v2, st.v3)
    st.v0 = st.v0 xor m

    st.ntail = 0

  let mlen = len(msg) - needed
  let rem = mlen and 7
  let maxoffs = mlen - rem

  var offs = needed
  while offs < maxoffs:
    let mi = loadu64(msg, offs)

    st.v3 = st.v3 xor mi
    sipround(st.v0, st.v1, st.v2, st.v3)
    sipround(st.v0, st.v1, st.v2, st.v3)
    st.v0 = st.v0 xor mi

    offs += 8

  var t = 0
  while t < rem:
    st.tail[t] = msg[offs+t]
    inc t
  st.ntail = rem

# helper
proc `|=`(m: var uint64, p: uint64) {.inline, noSideEffect.} =
  m = m or p

proc mkResult(st: var SipState, c, d: int): array[8, byte] =
  var v0 = st.v0
  var v1 = st.v1
  var v2 = st.v2
  var v3 = st.v3

  var mfinal = (st.length.uint64 mod 256) shl 56

  if 7 <= st.ntail:
    mfinal |= (st.tail[ 6].uint64 shl 48)
  if 6 <= st.ntail:
    mfinal |= (st.tail[ 5].uint64 shl 40)
  if 5 <= st.ntail:
    mfinal |= (st.tail[ 4].uint64 shl 32)
  if 4 <= st.ntail:
    mfinal |= (st.tail[ 3].uint64 shl 24)
  if 3 <= st.ntail:
    mfinal |= (st.tail[ 2].uint64 shl 16)
  if 2 <= st.ntail:
    mfinal |= (st.tail[ 1].uint64 shl  8)
  if 1 <= st.ntail:
    mfinal |= (st.tail[ 0].uint64 shl  0)

  v3 = v3 xor mfinal

  for i in 0..<c:
    sipround(v0, v1, v2, v3)
  #sipround(v0, v1, v2, v3)

  v0 = v0 xor mfinal

  # finalize

  v2 = v2 xor 0xff

  for i in 0..<d:
    sipround(v0, v1, v2, v3)
  #sipround(v0, v1, v2, v3)
  #sipround(v0, v1, v2, v3)
  #sipround(v0, v1, v2, v3)

  let h = v0 xor v1 xor v2 xor v3

  result = [
    (h shr  0).byte,
    (h shr  8).byte,
    (h shr 16).byte,
    (h shr 24).byte,
    (h shr 32).byte,
    (h shr 40).byte,
    (h shr 48).byte,
    (h shr 56).byte,
  ]

proc initSipState*(key0, key1: uint64): SipState =
  ## initializes a SipState using two uint64s
  result.k0 = key0
  result.k1 = key1
  result.length = 0
  result.v0 = key0 xor 0x736f6d6570736575'u64
  result.v1 = key1 xor 0x646f72616e646f6d'u64
  result.v2 = key0 xor 0x6c7967656e657261'u64
  result.v3 = key1 xor 0x7465646279746573'u64
  result.ntail = 0

proc input*(st: var SipState, msg: openarray[byte]) =
  ## inputs a byte array message into `st`
  st.addInput(msg)

proc input*(st: var SipState, msg: string) =
  ## inputs a string containing byte information into `st`
  var msgb = newSeq[byte]()
  for i in msg:
    msgb.add(ord(i).byte)
  st.addInput(msgb)

proc inputHex*(st: var SipState, msg: string) =
  ## inputs a string with hex information into `st`
  assert(len(msg) mod 2 == 0)
  var msgb = newSeq[byte](msg.len div 2)
  for i in 0..<msgb.len:
    msgb[i] = parseHexInt(msg[i*2..i*2+1]).byte
  st.input(msgb)

proc gethash*(st: var SipState, c = 2, d = 4): array[8, byte] =
  ## returns the byte array of the SipHash of `st`
  result = st.mkResult(c, d)

proc gethashstr*(st: var SipState, c = 2, d = 4): string =
  ## returns the string-ified hex result of the SipHash of `st`
  let r = st.mkResult(c, d)
  var s = ""
  for b in r:
    s.add(toHex(b.int, 2).toLower)
  result = s

proc initSipState*(key: string): SipState =
  ## initializes a SipState with a hexadecimal string representing its keys
  assert(key.len == 32)
  var keyb = newSeq[byte](16)
  for i in 0..<16:
    let tmp = parseHexInt(key[i*2..i*2+1]).byte
    #echo "tmp: ", tmp
    keyb[i] = tmp
  #echo "keyb: ", keyb
  let key0 = loadu64(keyb, 0)
  let key1 = loadu64(keyb, 8)
  #echo "key0: ", toHex(key0.int,16)
  #echo "key1: ", toHex(key1.int,16)
  result = initSipState(key0, key1)

proc siphash*(key: string, c = 2, d = 4): string =
  ## produces a hash given a hexadecimal string representation of a 128-bit number
  var s: SipState
  s = initSipState(key)
  #echo "s.v0: ", s.v0
  result = gethashstr(s, c, d)

proc siphash*(key, message: string, c = 2, d = 4): string =
  ## produces a hash given a hexadecimal string representation of a 128-bit number
  var s: SipState
  s = initSipState(key)
  s.inputHex(message)
  #echo "s.v0: ", s.v0
  result = gethashstr(s, c, d)

proc siphash*(key0, key1: uint64, c = 2, d = 4): string =
  ## produces a hash given two uint64s (based on no input)
  var s = initSipState(key0, key1)
  result = gethashstr(s, c, d)

proc siphash*(key0, key1: uint64, message: openarray[byte], c = 2, d = 4): string =
  ## produces a hash given two uint64s (using message as input)
  var s = initSipState(key0, key1)
  s.input(message)
  result = gethashstr(s, c, d)

proc siphash*(key0, key1: uint64, message: string, c = 2, d = 4): string =
  ## produces a hash given two uint64s (using message as input hex)
  var s = initSipState(key0, key1)
  s.inputHex(message)
  result = gethashstr(s, c, d)

proc siphash24*(key0, key1: uint64): string =
  ## the number-form input of a SipHash-2-4
  result = siphash(key0, key1, 2, 4)
proc siphash48*(key0, key1: uint64): string =
  ## the number-form input of a SipHash-4-8
  result = siphash(key0, key1, 4, 8)
proc siphash24*(key0, key1: uint64, message: string): string =
  ## the number-form input of a SipHash-2-4
  result = siphash(key0, key1, message, 2, 4)
proc siphash48*(key0, key1: uint64, message: string): string =
  ## the number-form input of a SipHash-4-8
  result = siphash(key0, key1, message, 4, 8)
proc siphash24*(key, message: string): string =
  ## the hex string input version of a SipHash-2-4
  result = siphash(key, message, 2, 4)
proc siphash48*(key, message: string): string =
  ## the hex string input version of a SipHash-4-8
  result = siphash(key, message, 4, 8)

when isMainModule:
  let buf = newSeq[byte]()
  let k0 = 0x0706050403020100'u64
  let k1 = 0x0f0e0d0c0b0a0908'u64
  var inc = initSipState(k0,k1)
  var full = initSipState(k0,k1)
  #echo "inc.v0: ", inc.v0
  full.input(buf)
  assert(full.gethashstr() == "310e0edd47db6f72")
  assert(full.gethashstr() == inc.gethashstr())
  inc.input("\0")
  assert(inc.gethashstr() == "fd67dc93c539f874")
  var dah = initSipState("000102030405060708090A0B0C0D0E0F")
  dah.input(@[0xc7.byte,0x88,0xc9,0xea])
  assert(dah.gethashstr() == "7df80c7325d34646")
  var blah = initSipState("A8FC63780FB3BA3CA39580EEC5CB43B1")
  blah.inputHex("6018B63E6DBF9B")
  assert(blah.gethashstr() == "701bdf2ea1c82585")

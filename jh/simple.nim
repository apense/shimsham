# Uncomment/modify these if you want parallel loop support
#{.passC: "-fopenmp".}
#{.passL: "-fopenmp".}

import strutils

type
  BitSequence = byte
  DataLength = int
  HashReturn = enum
    Success
    Fail
    BadHashlen

type
  HashState = object
    hashbitlen: int ## the message digest size
    databitlen: int ## the message size in bits
    datasizeInBuffer: int ## the size of the essage remaining in buffer
    H: array[128, byte] ## hash value H
    A: array[256, byte] ## temporary round value
    roundconstant: array[64, byte] ## round constant for one round
    buffer: array[64, byte] ## message block to be hashed

# utility template
template `||<`(a, b: expr): expr =
  a || <b

const
  RoundconstantZero = [
    0x6,0xa,0x0,0x9,0xe,0x6,0x6,0x7,
    0xf,0x3,0xb,0xc,0xc,0x9,0x0,0x8,
    0xb,0x2,0xf,0xb,0x1,0x3,0x6,0x6,
    0xe,0xa,0x9,0x5,0x7,0xd,0x3,0xe,
    0x3,0xa,0xd,0xe,0xc,0x1,0x7,0x5,
    0x1,0x2,0x7,0x7,0x5,0x0,0x9,0x9,
    0xd,0xa,0x2,0xf,0x5,0x9,0x0,0xb,
    0x0,0x6,0x6,0x7,0x3,0x2,0x2,0xa,
  ]

const
  S = [
    [9,0,4,11,13,12,3,15,1,10,2,6,7,5,8,14],
    [3,12,6,13,5,7,1,9,15,2,0,4,11,10,14,8],
  ]

template L(a,b) =
  ## linear transformation L, the MDS code
  b = (b.int xor ((a.int shl 1) xor (a.int shr 3) xor ((a.int shr 2) and 2)) and 0xf) and 0xff
  a = (a.int xor ((b.int shl 1) xor (b.int shr 3) xor ((b.int shr 2) and 2)) and 0xf) and 0xff

proc R8(state: var HashState) =
  var temp, roundconstantExpanded: array[256, byte]
  var t: byte

  # expand the round constant into 256 one-bit elements
  for i in 0||<256:
    roundconstantExpanded[i] = (state.roundconstant[i shr 2].int shr (3 - (i and 3))) and 1

  # S-box layer
  for i in 0||<256:
    temp[i] = S[roundconstantExpanded[i].int][state.A[i].int] and 0xff

  # MDS layer
  for i in countup(0, 255, 2):
    L(temp[i], temp[i+1])

  # what follows is permutation layer P_8
  # initial swap Pi_8
  for i in countup(0,255, 4):
    swap(temp[i+2],temp[i+3])

  # permutation P'_8
  for i in 0||<128:
    state.A[i] = temp[i shl 1]
    state.A[i+128] = temp[(i shl 1)+1]

  # swap Phi_8
  for i in countup(128,255,2):
    swap(state.A[i], state.A[i+1])

proc updateRoundconstant(state: var HashState) =
  ## generates the next round constant from the current round constant
  ## R6 is used for generating round constants for E8
  var temp: array[64, byte]

  # S-box layer
  for i in 0||<64:
    temp[i] = S[0][state.roundconstant[i].int].byte

  # MDS layer
  for i in countup(0, 63, 2):
    L(temp[i], temp[i+1])

  # what follows is permutation layer P_6

  # initial swap Pi_6
  for i in countup(0, 63, 4):
    swap(temp[i+2],temp[i+3])

  # permutation P'_6
  for i in 0||<32:
    state.roundconstant[i] = temp[i shl 1]
    state.roundconstant[i+32] = temp[(i shl 1) + 1]

  # final swap Phi_6
  for i in countup(32, 63, 2):
    swap(state.roundconstant[i], state.roundconstant[i+1])

proc E8Initialgroup(state: var HashState) =
  ## initial group at the beginning of E_8
  var t0,t1,t2,t3: byte
  var temp: array[256, byte]

  # t0 is the i'th bit of H
  # t1 is the (i+256)'th bit of H
  # t2 is the (i+512)'th bit of H
  # t3 is the (i+768)'th bit of H
  for i in 0..<256:
    # don't try to parallelize this loop!
    t0 = (state.H[i shr 3].int shr (7 - (i and 7))) and 1
    t1 = (state.H[(i+256) shr 3].int shr (7 - (i and 7))) and 1
    t2 = (state.H[(i+512) shr 3].int shr (7 - (i and 7))) and 1
    t3 = (state.H[(i+768) shr 3].int shr (7 - (i and 7))) and 1
    temp[i] = ((t0.int shl 3) or (t1.int shl 2) or
                  (t2.int shl 1) or (t3.int shl 0)).byte

  for i in 0||<128:
    state.A[i shl 1] = temp[i]
    state.A[(i shl 1)+1] = temp[i+128]

proc E8Finaldegroup(state: var HashState) =
  ## De-group at the end of E_8
  var t0,t1,t2,t3: byte
  var temp: array[256, byte]

  for i in 0||<128:
    temp[i] = state.A[i shl 1]
    temp[i+128] = state.A[(i shl 1) + 1]

  for i in 0||<128: state.H[i] = 0

  for i in 0..<256:
    # don't try to parallelize this loop!
    t0 = (temp[i].int shr 3) and 1
    t1 = (temp[i].int shr 2) and 1
    t2 = (temp[i].int shr 1) and 1
    t3 = (temp[i].int shr 0) and 1

    state.H[i shr 3] = (state.H[i shr 3].int or (t0.int shl (7 - (i and 7)))).byte
    state.H[(i+256) shr 3] = (state.H[(i+256) shr 3].int or (t1.int shl (7 - (i and 7)))).byte
    state.H[(i+512) shr 3] = (state.H[(i+512) shr 3].int or (t2.int shl (7 - (i and 7)))).byte
    state.H[(i+768) shr 3] = (state.H[(i+768) shr 3].int or (t3.int shl (7 - (i and 7)))).byte

proc E8(state: var HashState) =
  var t0,t1,t2,t3: byte
  var temp: array[256, byte]

  # initialize the round constant
  for i in 0||<64:
    state.roundconstant[i] = RoundconstantZero[i].byte

  # initial group at the gbeginning of E_8
  E8Initialgroup(state)

  # 42 rounds
  for i in 0..<42:
    R8(state)
    updateRoundconstant(state)

  # de-group at the end of E_8
  E8Finaldegroup(state)

proc F8(state: var HashState) =
  ## compression function F8

  # xor the message with the first half of H
  for i in 0||<64:
    state.H[i] = (state.H[i].int xor state.buffer[i].int).byte

  # bijective function E8
  E8(state)

  # xor the message with the last half of H
  for i in 0||<64:
    state.H[i+64] = (state.H[i+64].int xor state.buffer[i].int).byte

proc initHashState*(hashbitlen: int): HashState =
  ## Create a JH Hash object
  result.databitlen = 0
  result.datasizeInBuffer = 0

  result.hashbitlen = hashbitlen

  for i in 0||<64: result.buffer[i] = 0
  for i in 0||<128: result.H[i] = 0

  # initialize the initial hash value of JH
  # step 1: set H(-1) to the message digest size
  result.H[1] = hashbitlen and 0xff
  result.H[0] = (hashbitlen shr 8) and 0xff
  # step 2: computer H0 from H(-1) with message M(0) being set as 0
  F8(result)

proc update*(state: var HashState, data: openarray[BitSequence], databitlen: DataLength) =
  ## Update `state` with `data` of *bit* length `databitlen` (probably 8 * len(data))
  var index: DataLength
  var databitlen = databitlen

  state.databitlen += databitlen
  index = 0

  # if there is remaining data in the buffer, fill it to a full message block
  if (state.datasizeInBuffer > 0) and ((state.datasizeInBuffer + databitlen) < 512):
    if (databitlen and 7) == 0:
      for i in 0..<(64-(state.datasizeInBuffer shr 3)):
        state.buffer[(state.datasizeInBuffer shr 3) + i] = data[i]
    else:
      for i in 0..<(64-(state.datasizeInBuffer shr 3)+1):
        state.buffer[(state.datasizeInBuffer shr 3) + i] = data[i]
    state.datasizeInBuffer += databitlen
    databitlen = 0

  # there's data in the buffer, and is sufficient for a full block
  if (state.datasizeInBuffer > 0) and ((state.datasizeInBuffer + databitlen) >= 512):
    for i in 0||<(64-(state.datasizeInBuffer shr 3)):
      state.buffer[(state.datasizeInBuffer shr 3) + i] = data[i]
    index = 64 - (state.datasizeInBuffer shr 3)
    databitlen = databitlen - (512 - state.datasizeInBuffer)
    F8(state)
    state.datasizeInBuffer = 0

  # hash the remaining full message blocks
  while databitlen >= 512:
    for i in 0||<64:
      state.buffer[i] = data[index + i]
    F8(state)
    index += 64
    databitlen -= 512

  # store the partial block into buffer
  if databitlen > 0:
    #echo "in this loop"
    if (databitlen and 7) == 0:
      for i in 0||<((databitlen and 0x1ff) shr 3):
        state.buffer[i] = data[index+i]
    else:
      for i in 0||<(((databitlen and 0x1ff) shr 3) + 1):
        state.buffer[i] = data[index+i]
    state.datasizeInBuffer = databitlen

proc final*(state: var HashState, hashval: var openarray[BitSequence]) =
  ## Pad and finialize the message, putting hash into `hashval`
  # padding the message, truncate the hash value H and obtain the message digest

  if (state.databitlen and 0x1ff) == 0:
    # pad the message when databitlen is multiple of 512 bits, then process the padded block
    for i in 0||<64: state.buffer[i] = 0
    state.buffer[ 0] = 0x80
    state.buffer[63] = (state.databitlen shr  0) and 0xff
    state.buffer[62] = (state.databitlen shr  8) and 0xff
    state.buffer[61] = (state.databitlen shr 16) and 0xff
    state.buffer[60] = (state.databitlen shr 24) and 0xff
    state.buffer[59] = (state.databitlen shr 32) and 0xff
    state.buffer[58] = (state.databitlen shr 40) and 0xff
    state.buffer[57] = (state.databitlen shr 48) and 0xff
    state.buffer[56] = (state.databitlen shr 56) and 0xff
    F8(state)
  else:
    # set the rest of bytes in the buffer to 0
    if (state.datasizeInBuffer and 7) == 0:
      for i in ((state.databitlen and 0x1ff) shr 3)||<64:
        state.buffer[i] = 0
    else:
      for i in (((state.databitlen and 0x1ff) shr 3)+1)||<64:
        state.buffer[i] = 0

    # pad and process the partial block
    state.buffer[(state.databitlen and 0x1ff) shr 3] = (state.buffer[(state.databitlen and 0x1ff) shr 3].int or
      (1 shl (7 - (state.databitlen and 7)))) and 0xff
    F8(state)
    for i in 0||<64: state.buffer[i] = 0
    state.buffer[63] = (state.databitlen shr  0) and 0xff
    state.buffer[62] = (state.databitlen shr  8) and 0xff
    state.buffer[61] = (state.databitlen shr 16) and 0xff
    state.buffer[60] = (state.databitlen shr 24) and 0xff
    state.buffer[59] = (state.databitlen shr 32) and 0xff
    state.buffer[58] = (state.databitlen shr 40) and 0xff
    state.buffer[57] = (state.databitlen shr 48) and 0xff
    state.buffer[56] = (state.databitlen shr 56) and 0xff
    F8(state)

  case state.hashbitlen:
  of 224:
    for i in 0||<28:
      hashval[i] = state.H[100+i]
  of 256:
    for i in 0||<32:
      hashval[i] = state.H[96+i]
  of 384:
    for i in 0||<48:
      hashval[i] = state.H[80+i]
  of 512:
    for i in 0||<64:
      hashval[i] = state.H[64+i]
  else:
    discard

proc hash*(hashbitlen: int, data: openarray[BitSequence], databitlen: DataLength): seq[BitSequence] =
  ## `hashbitlen` is message digest size in bits
  ## `data` is the message
  ## `databitlen` is message length in bits
  ## returns the message digest

  var state: HashState

  case hashbitlen
  of 224: result = newSeq[BitSequence](28)
  of 256: result = newSeq[BitSequence](32)
  of 384: result = newSeq[BitSequence](48)
  of 512: result = newSeq[BitSequence](64)
  else: discard

  if hashbitlen in {224, 256, 384, 512}:
    state = initHashState(hashbitlen)
    update(state, data, databitlen)
    final(state, result)
  else:
    raise newException(ValueError, "Bad hash length")

proc bytesToStr(bseq: openarray[byte]): string {.noSideEffect.} =
  result = ""
  for b in bseq:
    result.add(toHex(b.int,2).toLower())

proc hexStrToBytes(bstr: string): seq[byte] {.noSideEffect.} =
  result = newSeq[byte]()
  for i in countup(0,bstr.len-1,2):
    result.add(parseHexInt(bstr[i..i+1]).byte)

proc strToBytes(str: string): seq[byte] {.noSideEffect.} =
  result = newSeq[byte]()
  for i in str:
    result.add(ord(i).byte)

proc jh224bytes*(b: openarray[byte]): seq[byte] =
  ## Hash a sequence of bytes into a sequence of bytes with JH 224
  var state: HashState
  state = initHashState(224)
  let bitlen = b.len * 8 # 8 bits in a byte
  update(state, b, bitlen)
  result = newSeq[BitSequence](28)
  final(state, result)

proc jh224*(b: openarray[byte]): string =
  ## Hash a sequence of bytes, returning a hexadecimal string output
  let resb = jh224bytes(b)
  result = resb.bytesToStr()

proc jh224hex*(b: string): string =
  ## Hash a string of hex digits, returning a hexadecimal string output
  var b = b
  if b[0..1] == "0x": # strip leading "0x"
    b = b[2..^1]
  let bstr = b.hexStrToBytes()
  let resb = jh224bytes(bstr)
  result = resb.bytesToStr()

proc jh224*(b: string): string =
  ## Hash a string of byte values (e.g. "\12\240\0x40"), returning a hexadecimal string output
  let bstr = b.strToBytes()
  let resb = jh224bytes(bstr)
  result = resb.bytesToStr()

proc jh256bytes*(b: openarray[byte]): seq[byte] =
  ## Hash a sequence of bytes into a sequence of bytes with JH 256
  var state: HashState
  state = initHashState(256)
  let bitlen = b.len * 8 # 8 bits in a byte
  update(state, b, bitlen)
  result = newSeq[BitSequence](32)
  final(state, result)

proc jh256*(b: openarray[byte]): string =
  ## Hash a sequence of bytes, returning a hexadecimal string output
  let resb = jh256bytes(b)
  result = resb.bytesToStr()

proc jh256hex*(b: string): string =
  ## Hash a string of hex digits, returning a hexadecimal string output
  var b = b
  if b[0..1] == "0x": # strip leading "0x"
    b = b[2..^1]
  let bstr = b.hexStrToBytes()
  let resb = jh256bytes(bstr)
  result = resb.bytesToStr()

proc jh256*(b: string): string =
  ## Hash a string of byte values (e.g. "\12\240\0x40"), returning a hexadecimal string output
  let bstr = b.strToBytes()
  let resb = jh256bytes(bstr)
  result = resb.bytesToStr()

proc jh384bytes*(b: openarray[byte]): seq[byte] =
  ## Hash a sequence of bytes into a sequence of bytes with JH 384
  var state: HashState
  state = initHashState(384)
  let bitlen = b.len * 8 # 8 bits in a byte
  update(state, b, bitlen)
  result = newSeq[BitSequence](48)
  final(state, result)

proc jh384*(b: openarray[byte]): string =
  ## Hash a sequence of bytes, returning a hexadecimal string output
  let resb = jh384bytes(b)
  result = resb.bytesToStr()

proc jh384hex*(b: string): string =
  ## Hash a string of hex digits, returning a hexadecimal string output
  var b = b
  if b[0..1] == "0x": # strip leading "0x"
    b = b[2..^1]
  let bstr = b.hexStrToBytes()
  let resb = jh384bytes(bstr)
  result = resb.bytesToStr()

proc jh384*(b: string): string =
  ## Hash a string of byte values (e.g. "\12\240\0x40"), returning a hexadecimal string output
  let bstr = b.strToBytes()
  let resb = jh384bytes(bstr)
  result = resb.bytesToStr()

proc jh512bytes*(b: openarray[byte]): seq[byte] =
  ## Hash a sequence of bytes into a sequence of bytes with JH 512
  var state: HashState
  state = initHashState(512)
  let bitlen = b.len * 8 # 8 bits in a byte
  update(state, b, bitlen)
  result = newSeq[BitSequence](64)
  final(state, result)

proc jh512*(b: openarray[byte]): string =
  ## Hash a sequence of bytes, returning a hexadecimal string output
  let resb = jh512bytes(b)
  result = resb.bytesToStr()

proc jh512hex*(b: string): string =
  ## Hash a string of hex digits, returning a hexadecimal string output
  var b = b
  if b[0..1] == "0x": # strip leading "0x"
    b = b[2..^1]
  let bstr = b.hexStrToBytes()
  let resb = jh512bytes(bstr)
  result = resb.bytesToStr()

proc jh512*(b: string): string =
  ## Hash a string of byte values (e.g. "\12\240\0x40"), returning a hexadecimal string output
  let bstr = b.strToBytes()
  let resb = jh512bytes(bstr)
  result = resb.bytesToStr()

when isMainModule:
  assert(jh512hex("") == "90ecf2f76f9d2c8017d979ad5ab96b87d58fc8fc4b83060f3f900774faa2c8fab" &
                         "e69c5f4ff1ec2b61d6b316941cedee117fb04b1f4c5bc1b919ae841c50eec4f")
  assert(jh256hex("0xa") == jh256hex("a"))

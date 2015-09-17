import strtabs, strutils, unsigned

const
  BlockSize = 128
  DigestSize = 64

type
  ShaObject* = object {.inheritable.}
    digest*: array[8, uint64]
    countLo*: int
    countHi*: int
    data*: array[BlockSize, char]
    local*: int
    digestSize*: int

type
  Sha512* = object of ShaObject
    sha: ShaObject
    ds*, bs*: int
  Sha384* = object of Sha512

template ROR64(x,y): expr =
  uint64(((x and 0xffffffffffffffff'u64) shr (y and 63'u64)) or
    (x shl (64'u64 - (y and 63'u64)))) and 0xffffffffffffffff'u64

template Ch(x,y,z): expr =
  uint64(z xor (x and (y xor z)))

template Maj(x,y,z): expr =
  uint64(((x or y) and z) or (x and y))

template S(x, n): expr =
  uint64(ROR64(uint64(x), uint64(n)))

template R(x, n): expr =
  uint64((x and 0xffffffffffffffff'u64) shr n)

template Sigma0(x): expr =
  uint64(S(x, 28) xor S(x, 34) xor S(x, 39))

template Simga1(x): expr =
  uint64(S(x, 14) xor S(x, 18) xor S(x, 41))

template Gamma0(x): expr =
  uint64(S(x, 1) xor S(x, 8) xor R(x, 7))

template Gamma1(x): expr =
  uint64(S(x, 19) xor S(x, 61) xor R(x, 6))

proc shaInit(): ShaObject =
  result.digest = [0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64, 0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
    0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64, 0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64]
  result.countLo = 0
  result.countHi = 0
  result.local = 0
  result.digestSize = 64

proc sha384Init(): ShaObject =
  result.digest = [0xcbbb9d5dc1059ed8'u64, 0x629a292a367cd507'u64, 0x9159015a3070dd17'u64, 0x152fecd8f70e5939'u64,
    0x67332667ffc00b31'u64, 0x8eb44a8768581511'u64, 0xdb0c2e0d64f98fa7'u64, 0x47b5481dbefa4fa4'u64]
  result.countLo = 0
  result.countHi = 0
  result.local = 0
  result.digestSize = 48

proc shaTransform(shaInfo: var ShaObject) {.noSideEffect.} =
  var W = newSeq[uint64]()

  var d = shaInfo.data
  for i in 0..15:
    let m: uint64 = uint64(ord(d[8*i]) shl 56) + uint64(ord(d[8*i+1]) shl 48) + uint64(ord(d[8*i+2]) shl 40) +
      uint64(ord(d[8*i+3]) shl 32) + uint64(ord(d[8*i+4]) shl 24) + uint64(ord(d[8*i+5]) shl 16) +
      uint64(ord(d[8*i+6]) shl 8) + (ord(d[8*i+7]))
    W.add(m)

  for i in 16..79:
    let m = uint64(Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16]) and uint64(0xffffffffffffffff)
    W.add(m)

  var ss = shaInfo.digest

  proc RND(a, b, c: uint64, d: var uint64, e, f, g: uint64,
    h: var uint64, i, ki: uint64): tuple[d, h: uint64] {.noSideEffect.} =
    var t0 = (h + Simga1(e) + Ch(e, f, g) + ki + W[int(i)]) and
      0xffffffffffffffff'u64
    var t1 = (Sigma0(a) + Maj(a, b, c)) and 0xffffffffffffffff'u64
    d = (d + t0) and 0xffffffffffffffff'u64
    h = (t0 + t1) and 0xffffffffffffffff'u64
    result = (d and 0xffffffffffffffff'u64, h and 0xffffffffffffffff'u64)

  var res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],
    0,0x428a2f98d728ae22'u64)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],
    1,0x7137449123ef65cd'u64)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],
    2,0xb5c0fbcfec4d3b2f'u64)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],
    3,0xe9b5dba58189dbbc'u64)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],
    4,0x3956c25bf348b538'u64)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],
    5,0x59f111f1b605d019'u64)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],
    6,0x923f82a4af194f9b'u64)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],
    7,0xab1c5ed5da6d8118'u64)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],
    8,0xd807aa98a3030242'u64)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],
    9,0x12835b0145706fbe'u64)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],
    10,0x243185be4ee4b28c'u64)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],
    11,0x550c7dc3d5ffb4e2'u64)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],
    12,0x72be5d74f27b896f'u64)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],
    13,0x80deb1fe3b1696b1'u64)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],
    14,0x9bdc06a725c71235'u64)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],15,
    0xc19bf174cf692694'u64)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],16,
    0xe49b69c19ef14ad2'u64)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],17,
    0xefbe4786384f25e3'u64)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],18,
    0x0fc19dc68b8cd5b5'u64)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],19,
    0x240ca1cc77ac9c65'u64)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],20,
    0x2de92c6f592b0275'u64)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],21,
    0x4a7484aa6ea6e483'u64)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],22,
    0x5cb0a9dcbd41fbd4'u64)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],23,
    0x76f988da831153b5'u64)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],24,
    0x983e5152ee66dfab'u64)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],25,
    0xa831c66d2db43210'u64)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],26,
    0xb00327c898fb213f'u64)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],27,
    0xbf597fc7beef0ee4'u64)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],28,
    0xc6e00bf33da88fc2'u64)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],29,
    0xd5a79147930aa725'u64)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],30,
    0x06ca6351e003826f'u64)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],31,
    0x142929670a0e6e70'u64)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],32,
    0x27b70a8546d22ffc'u64)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],33,
    0x2e1b21385c26c926'u64)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],34,
    0x4d2c6dfc5ac42aed'u64)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],35,
    0x53380d139d95b3df'u64)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],36,
    0x650a73548baf63de'u64)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],37,
    0x766a0abb3c77b2a8'u64)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],38,
    0x81c2c92e47edaee6'u64)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],39,
    0x92722c851482353b'u64)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],40,
    0xa2bfe8a14cf10364'u64)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],41,
    0xa81a664bbc423001'u64)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],42,
    0xc24b8b70d0f89791'u64)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],43,
    0xc76c51a30654be30'u64)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],44,
    0xd192e819d6ef5218'u64)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],45,
    0xd69906245565a910'u64)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],46,
    0xf40e35855771202a'u64)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],47,
    0x106aa07032bbd1b8'u64)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],48,
    0x19a4c116b8d2d0c8'u64)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],49,
    0x1e376c085141ab53'u64)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],50,
    0x2748774cdf8eeb99'u64)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],51,
    0x34b0bcb5e19b48a8'u64)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],52,
    0x391c0cb3c5c95a63'u64)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],53,
    0x4ed8aa4ae3418acb'u64)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],54,
    0x5b9cca4f7763e373'u64)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],55,
    0x682e6ff3d6b2b8a3'u64)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],56,
    0x748f82ee5defb2fc'u64)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],57,
    0x78a5636f43172f60'u64)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],58,
    0x84c87814a1f0ab72'u64)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],59,
    0x8cc702081a6439ec'u64)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],60,
    0x90befffa23631e28'u64)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],61,
    0xa4506cebde82bde9'u64)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],62,
    0xbef9a3f7b2c67915'u64)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],63,
    0xc67178f2e372532b'u64)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],64,
    0xca273eceea26619c'u64)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],65,
    0xd186b8c721c0c207'u64)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],66,
    0xeada7dd6cde0eb1e'u64)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],67,
    0xf57d4f7fee6ed178'u64)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],68,
    0x06f067aa72176fba'u64)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],69,
    0x0a637dc5a2c898a6'u64)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],70,
    0x113f9804bef90dae'u64)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],71,
    0x1b710b35131c471b'u64)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],72,
    0x28db77f523047d84'u64)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],73,
    0x32caab7b40c72493'u64)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],74,
    0x3c9ebe0a15c9bebc'u64)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],75,
    0x431d67c49c100d4c'u64)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],76,
    0x4cc5d4becb3e42b6'u64)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],77,
    0x597f299cfc657e2a'u64)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],78,
    0x5fcb6fab3ad6faec'u64)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],79,
    0x6c44198c4a475817'u64)
  ss[4] = res.d
  ss[0] = res.h

  var dig: array[8, uint64]
  for i,x in shaInfo.digest:
    dig[i] = ((x + ss[i]) and 0xffffffffffffffff'u64)
  shaInfo.digest = dig

proc shaUpdate*(shaInfo: var ShaObject, buffer: seq[char]) {.noSideEffect.} =
  var count = len(buffer)
  var bufferIdx = 0
  var clo = (shaInfo.countLo + (count shl 3)) and 0xffffffff
  if(clo < shaInfo.countLo):
    inc(shaInfo.countHi)
  shaInfo.countLo = clo

  shaInfo.countHi += (count shr 29)

  if(shaInfo.local != 0):
    var i = BlockSize - shaInfo.local
    if(i > count):
      i = count

    # copy buffer
    for i,b in buffer[bufferIdx..bufferIdx+i-1]:
      shaInfo.data[shaInfo.local + i] = b

    count -= i
    bufferIdx += i

    shaInfo.local += i
    if(shaInfo.local == BlockSize):
      shaTransform(shaInfo)
      shaInfo.local = 0
    else:
      return

  while(count >= BlockSize):
    # copy buffer
    for i,b in buffer[bufferIdx..bufferIdx+BlockSize-1]:
      shaInfo.data[i] = b
    count -= BlockSize
    bufferIdx += BlockSize
    shaTransform(shaInfo)

  # copy buffer
  var pos = shaInfo.local
  for i,b in buffer[bufferIdx..bufferIdx+count-1]:
    shaInfo.data[pos+i] = b
  shaInfo.local = count

proc shaFinal(shaInfo: var ShaObject): string {.noSideEffect.} =
  var (loBitCount, hiBitCount) = (shaInfo.countLo, shaInfo.countHi)

  var count = (loBitCount shr 3) and 0x7f
  shaInfo.data[count] = chr(0x80)
  inc(count)

  if count > BlockSize - 16:
    # zero the bytes in data after the count
    for i in count..BlockSize-1:
      shaInfo.data[i] = chr(0)
    shaTransform(shaInfo)
    # zero bytes in data
    for i,b in shaInfo.data:
      shaInfo.data[i] = chr(0)
  else:
    for i in count..BlockSize-1:
      shaInfo.data[i] = chr(0)

  shaInfo.data[112] = chr(0)
  shaInfo.data[113] = chr(0)
  shaInfo.data[114] = chr(0)
  shaInfo.data[115] = chr(0)
  shaInfo.data[116] = chr(0)
  shaInfo.data[117] = chr(0)
  shaInfo.data[118] = chr(0)
  shaInfo.data[119] = chr(0)

  shaInfo.data[120] = chr((hiBitCount shr 24) and 0xff)
  shaInfo.data[121] = chr((hiBitCount shr 16) and 0xff)
  shaInfo.data[122] = chr((hiBitCount shr  8) and 0xff)
  shaInfo.data[123] = chr((hiBitCount shr  0) and 0xff)
  shaInfo.data[124] = chr((loBitCount shr 24) and 0xff)
  shaInfo.data[125] = chr((loBitCount shr 16) and 0xff)
  shaInfo.data[126] = chr((loBitCount shr  8) and 0xff)
  shaInfo.data[127] = chr((loBitCount shr  0) and 0xff)

  shaTransform(shaInfo)

  var dig = newSeq[char]()
  for i in shaInfo.digest:
    dig = dig & @[chr((i shr 56) and 0xff), chr((i shr 48) and 0xff),
      chr((i shr 40) and 0xff),chr((i shr 32) and 0xff),
      chr((i shr 24) and 0xff), chr((i shr 16) and 0xff),
      chr((i shr 8) and 0xff), chr(i and 0xff)]

  var res = ""
  for i in dig:
    res.add(i)

  result = res

proc initSha512*(s = ""): Sha512 {.noSideEffect.} =
  result.ds = DigestSize
  result.bs = BlockSize
  result.sha = shaInit()
  var buf = newSeq[char]()
  if s != nil:
    for c in s:
      buf.add(c)
    shaUpdate(result.sha, buf)

proc initSha384*(s = ""): Sha384 {.noSideEffect.} =
  result.ds = 48
  result.bs = BlockSize
  result.sha = sha384Init()
  var buf = newSeq[char]()
  if s != nil:
    for c in s:
      buf.add(c)
    shaUpdate(result.sha, buf)

proc update*(s: var Sha512, sc: seq[char]) {.noSideEffect.} =
  shaUpdate(s.sha, sc)

proc update*(s: var Sha512, str: string) {.noSideEffect.} =
  var buf = newSeq[char]()
  for c in str:
    buf.add(c)
  shaUpdate(s.sha, buf)

proc strDigest(s: var Sha512): string {.noSideEffect.} =
  result = shaFinal(s.sha)[0..s.sha.digestSize-1]

proc hexDigest(s: var Sha512): string {.noSideEffect.} =
  var dig = s.strDigest
  result = ""
  for i in dig:
    result.add(toLower(toHex(ord(i), 2)))

proc hexDigest*(s: Sha512): string {.noSideEffect.} =
  var m = s
  result = m.hexDigest

proc `$`*(s: Sha512): string {.noSideEffect.} =
  result = s.hexDigest

proc `$`*(s: Sha384): string {.noSideEffect.} =
  result = s.hexDigest

proc sha512*(s = ""): string {.noSideEffect.} =
  let hash = initSha512(s)
  result = $hash

proc sha384*(s = ""): string {.noSideEffect.} =
  result = initSha384(s).hexDigest

when isMainModule:
  var s = initSha512()
  let astr = "just a test string"

  assert(s.hexDigest == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36" &
    "ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
  s = initSha512("just a test string")
  assert(s.hexDigest == "68be4c6664af867dd1d01c8d77e963d87d77b702400c8fabae355a41b89" &
    "27a5a5533a7f1c28509bbd65c5f3ac716f33be271fbda0ca018b71a84708c9fae8a53")
  s = initSha512(astr)
  s.update(astr)
  assert(s.hexDigest == "341aeb668730bbb48127d5531115f3c39d12cb9586a6ca770898398aff2" &
    "411087cfe0b570689adf328cddeb1f00803acce6737a19f310b53bbdb0320828f75bb")
  assert(sha384() == "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1" &
    "da274edebfe76f65fbd51ad2f14898b95b")

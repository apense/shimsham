import unsigned
import endians
## Ported from https://github.com/dchest/blake2s

const
  BlockSize*    = 64 ## block size of algorithm
  Size*         = 32.byte ## maximum digest size
  SaltSize*     = 8 ## maximum salt size
  PersonSize*   = 8 ## maximum personalization string size
  KeySize*      = 32 ## maximum size of key

type
  Blake2S* = object
    h*: array[8, uint32] ## current chain value
    t*: array[2, uint32] ## message bytes counter
    f*: array[2, uint32] ## finalization flags
    x*: array[BlockSize, byte] ## buffer for data not yet compressed
    nx*: int ## number of bytes in buffer

    ih*: array[8, uint32] ## initial chain value (after config)
    paddedKey*: array[BlockSize, byte] ## copy of key, padded with zeros
    isKeyed*: bool ## indicates whether hash was keyed
    size*: byte ## digest size in bytes
    isLastNode*: bool ## indicates processing of the last node in tree hashing

const
  IV*: array[8, uint32] = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32,
  ]

type
  Tree* = ref object ## represents parameters for tree hashing
    fanout*: byte ## fanout
    maxDepth*: byte ## maximal depth
    leafSize*: uint32 ## leaf maximal byte length (0 for unlimited)
    nodeOffset*: uint64 ## node offset (0 for first, leftmost, or leaf), max of 2⁴⁸-1
    nodeDepth*: byte ## node depth (0 for leaves)
    innerHashSize*: byte ## inner hash byte length
    isLastNode*: bool ## indicates processing of the last node of layer
  Config* = ref object ## used to configure hash function parameters and keying
    size*: byte ## digest size (if zero, default size of 32 bytes is used)
    key*: seq[byte] ## key for prefix-MAC
    salt*: seq[byte] ## salt (if < 8 bytes, padded with zeros)
    person*: seq[byte] ## personalization (if < 8 bytes, padded with zeros)
    tree*: Tree

let DefaultConfig* = Config(size: Size)

type ConfigError = object of Exception

proc verifyConfig(c: Config) {.raises: [ConfigError].} =
  if c.size > Size:
    raise newException(ConfigError, "digest size is too large")
  if c.key.len > KeySize:
    raise newException(ConfigError, "key is too large")
  if c.salt.len > SaltSize:
    # a smaller salt will be padded with zeros
    raise newException(ConfigError, "salt is too large")
  if c.person.len > PersonSize:
    # a smaller personalization will be padded with zeros
    raise newException(ConfigError, "personalization is too large")
  if c.tree != nil:
    # check tree configuration
    if c.tree.fanout == 1:
      raise newException(ConfigError, "fanout of 1 is not allowed in tree mode")
    if c.tree.maxDepth < 2:
      raise newException(ConfigError, "incorrect tree depth")
    if c.tree.innerHashSize < 1 or c.tree.innerHashSize > Size:
      raise newException(ConfigError, "incorrect tree inner hash size")
    if c.tree.nodeOffset > ((1 shl 48) - 1).uint64:
      raise newException(ConfigError, "tree node offset is too large")

template putUint32le*(b: var seq[byte], offset: int, val: uint32) =
  b[0+offset] = val.byte
  b[1+offset] = (val shr 8).byte
  b[2+offset] = (val shr 16).byte
  b[3+offset] = (val shr 24).byte

template getUint32le*(b: seq[byte], offset:int): uint32 =
  b[offset+0].uint32 or (b[offset+1].uint32 shl 8) or 
    (b[offset+2].uint32 shl 16) or (b[offset+3].uint32 shl 24)

import blocks

proc write*(d: var Blake2S, p: openarray[byte]) =
  var p = @p
  var nn = p.len
  var left = BlockSize - d.nx
  if p.len > left:
    # process buffer
    for i in 0..<left:
      d.x[d.nx+i] = p[i]
    p = p[left..^1]
    blocks(d, d.x)
    d.nx = 0

  # process full blocks except for the last one
  if p.len > BlockSize:
    var n = p.len and not(BlockSize-1)
    if n == p.len:
      n -= BlockSize
    blocks(d, p[0..n-1])
    p = p[n..^1]

  # fill buffer
  var amtCopied: int
  for i in 0..<min(len(d.x[d.nx..^1]), len(p)):
    d.x[d.nx+i] = p[i]
    inc amtCopied
  d.nx += amtCopied

proc reset(d: var Blake2S) =
  for i in 0..<8:
    d.h[i] = d.ih[i]
  d.t[0] = 0
  d.t[1] = 0
  d.f[0] = 0
  d.f[1] = 0
  d.nx   = 0
  if d.isKeyed:
    d.write(d.paddedKey)

proc initialize(d: var Blake2S, c: Config) =
  # create parameter block
  var p = newSeq[byte](BlockSize)
  p[0] = c.size
  p[1] = c.key.len.byte

  if c.salt != nil:
    for i in 0..<c.salt.len:
      p[16+i] = c.salt[i]

  if c.person != nil:
    for i in 0..<c.person.len:
      p[24+i] = c.person[i]

  if c.tree != nil:
    p[2] = c.tree.fanout
    p[3] = c.tree.maxDepth
    putUint32le(p, 4, c.tree.leafSize)
    p[8] = c.tree.nodeOffset.byte
    p[9] = (c.tree.nodeOffset shr 8).byte
    p[10] = (c.tree.nodeOffset shr 16).byte
    p[11] = (c.tree.nodeOffset shr 24).byte
    p[12] = (c.tree.nodeOffset shr 32).byte
    p[13] = (c.tree.nodeOffset shr 40).byte
    p[14] = c.tree.nodeDepth
    p[15] = c.tree.innerHashSize
  else:
    p[2] = 1
    p[3] = 1

  # initialize
  d.size = c.size
  for i in 0..<8:
    d.h[i] = IV[i] xor getUint32le(p,i*4)

  if c.tree != nil and c.tree.isLastNode:
    d.isLastNode = true

  # process key
  if c.key != nil:
    for i in 0..<min(d.paddedKey.len, c.key.len):
      d.paddedKey[i] = c.key[i]
    d.write(d.paddedKey)
    d.isKeyed = true

  # save a copy of initialized state
  for i in 0..<min(d.ih.len, d.h.len):
    d.ih[i] = d.h[i]


proc initBlake2S*(c: Config): Blake2S =
  var c = c
  if c == nil:
    c = DefaultConfig
  else:
    if c.size == 0:
      # set default size if it's zero
      c.size = Size
    c.verifyConfig()
  result.initialize(c)

proc new256(): Blake2S =
  var d: Blake2S
  d.initialize(DefaultConfig)
  result = d

proc newMAC(outBytes: byte, key: openarray[byte]): Blake2S =
  var d = initBlake2S(Config(size: outBytes, key: @key))
  result = d

proc checkSum*(d: var Blake2S): seq[byte] =
  # don't create unnecessary copies of the key
  if d.isKeyed:
    for i in 0..<d.paddedKey.len:
      d.paddedKey[i] = 0
  var decr = BlockSize.uint32 - d.nx.uint32
  if d.t[0] < decr:
    dec d.t[1]
  d.t[0] -= decr

  # pad buffer with zeros
  for i in d.nx..<d.x.len:
    d.x[i] = 0

  # set last block flag
  d.f[0] = 0xffffffff
  if d.isLastNode:
    d.f[1] = 0xffffffff

  # compress last block
  blocks(d, d.x)

  #echo "d.h: ", (@(d.h))

  var output = newSeq[byte](Size)
  var j = 0
  for _, s in d.h[0..((d.size-1) div 4).int]:
    putUint32le(output, j, s)
    inc j, 4

  result = output

proc sum256*(data: seq[byte]): seq[byte] =
  var d: Blake2S
  d.initialize(DefaultConfig)
  d.write(data)
  result = d.checkSum()

const blake2* = sum256

import strutils
var myseq: seq[byte] = @[]
var res = sum256(myseq)
var resstr = ""
for i in res:
  resstr.add(toHex(i.int, 2).toLower)
echo resstr
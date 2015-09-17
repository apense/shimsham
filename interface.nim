
type
  Digest* = object
    DigestSize*: int
    BlockSize*: int
    name*: string
    update*: proc(d: var Digest, input: byte)
    blockUpdate*: proc(d: var Digest, input: openarray[byte], inOff, length: int)
    finalize*: proc(d: var Digest, output: var openarray[byte], outOff: int)
    reset*: proc(d: var Digest)
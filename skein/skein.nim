import threefish/threefish
import ubi

include threefish/util
import copyfunc

import strutils

type
  SkeinConfiguration* = object
    numStateWords: int
    configValue: seq[uint64]
    configString: seq[uint64] ## State size for the configuration

type
  Skein* = object
    cipherStateWords*: int
    outputBytes*: int
    hashSize*: int
    bytesFilled*: int
    config: SkeinConfiguration
    cipher: Cipher
    ubiParameters: UbiTweak
    inputBuffer: seq[byte]
    cipherInput: seq[uint64]
    state: seq[uint64]

type
  InitializationType = enum
    Normal
    ZeroedState
    ChainedState
    ChainedConfig

type 
  StateSizeError = int
  OutputSizeError = int
  StatusError = int
  LengthError = int

proc raiseStateSizeError(s: StateSizeError) {.raises: [ValueError].} =
  raise newException(ValueError, "crypto/skein: invalid Skein state size " & $s)

proc raiseOutputSizeError(s: OutputSizeError) {.raises: [ValueError].} =
  raise newException(ValueError, "crypto/skein: invalid Skein output size " & $s)

proc raiseStatusError(s: StatusError) {.raises: [ValueError].} =
  raise newException(ValueError, "crypto/skein: partial byte only on last data block")

proc raiseLengthError(s: LengthError) {.raises: [ValueError].} =
  raise newException(ValueError, "crypto/skein: length of input buffer does not match bit length: " & $s)

const
  Skein256*  = 256
  Skein512*  = 512
  Skein1024* = 1024

var Schema = [ord('S').byte, ord('H'), ord('A'), ord('3')]

const MaxSkeinStateWords = Skein1024 div 64

var NullStateWords: array[MaxSkeinStateWords, uint64]

proc initSkeinConfiguration*(sk: Skein): SkeinConfiguration =
  result.numStateWords = sk.cipherStateWords
  result.configValue = newSeq[uint64](result.numStateWords)
  result.configString = newSeq[uint64](result.numStateWords)
  result.configString[1] = (sk.hashSize).uint64

proc generateConfiguration*(c: var SkeinConfiguration) =
  var tweak = initUbiTweak()

  # initialize the tweak value
  tweak.startNewBlockType(Config)
  tweak.setFinalBlock(true)
  tweak.setBitsProcessed(32)

  var cipher = threefish.newSize(c.numStateWords * 64)
  cipher.setTweak(tweak.getTweak())
  cipher.encrypt(c.configValue, c.configString)

  c.configValue[0] = c.configValue[0] xor c.configString[0]
  c.configValue[1] = c.configValue[1] xor c.configString[1]
  c.configValue[2] = c.configValue[2] xor c.configString[2]

proc generateConfigurationState*(c: var SkeinConfiguration, initialState: openarray[uint64]) =
  var tweak = initUbiTweak()

  # initialize the tweak value
  tweak.startNewBlockType(Config)
  tweak.setFinalBlock(true)
  tweak.setBitsProcessed(32)

  var cipher = threefish.newTweak(initialState, tweak.getTweak())
  cipher.encrypt(c.configValue, c.configString)

  c.configValue[0] = c.configValue[0] xor c.configString[0]
  c.configValue[1] = c.configValue[1] xor c.configString[1]
  c.configValue[2] = c.configValue[2] xor c.configString[2]

proc setSchema(c: var SkeinConfiguration, schema: openarray[byte]) =
  var n = c.configString[0]

  # clear the schema bytes
  n = n and not 0xffffffff'u64
  # set schema bytes
  n = schema[3].uint64 shl 24
  n = n or (schema[2].uint64 shl 16)
  n = n or (schema[1].uint64 shl  8)
  n = n or (schema[0].uint64)

  c.configString[0] = n

proc setVersion(c: var SkeinConfiguration, version: int) =
  c.configString[0] = c.configString[0] and not (0x03'u64 shl 32)
  c.configString[0] = c.configString[0] or (version.uint64 shl 32)

proc setTreeLeafSize(c: var SkeinConfiguration, size: byte) =
  c.configString[2] = c.configString[2] and not 0xff'u64
  c.configString[2] = c.configString[2] or size.uint64

proc setTreeFanOutSize(c: var SkeinConfiguration, size: byte) =
  c.configString[2] = c.configString[2] and not (0xff'u64 shl 8)
  c.configString[2] = c.configString[2] or (size.uint64 shl 8)

proc setMaxTreeHeigh(c: var SkeinConfiguration, height: byte) =
  c.configString[2] = c.configString[2] and not (0xff'u64 shl 16)
  c.configString[2] = c.configString[2] or (height.uint64 shl 16)

proc initialize(s: var Skein) =
  # copy the configuration value to the state
  for i in 0..<s.state.len:
    s.state[i] = s.config.configValue[i]
  # set up tweak for message block
  s.ubiParameters.startNewBlockType(Message.uint64)
  s.bytesFilled = 0

proc initializeWithState(s: var Skein, externalState: openarray[uint64]) =
  copy(s.state, externalState)
  # set up tweak for message block
  s.ubiParameters.startNewBlockType(Message.uint64)
  s.bytesFilled = 0

proc setup(s: var Skein, stateSize, outputSize: int) =
  s.cipherStateWords = stateSize div 64

  s.hashSize = outputSize
  s.outputBytes = (outputSize + 7) div 8

  # figure out which cipher we need
  s.cipher = threefish.newSize(stateSize)

  # allocate buffers
  s.inputBuffer = newSeq[byte](s.cipherStateWords*8)
  s.cipherInput = newSeq[uint64](s.cipherStateWords)
  s.state = newSeq[uint64](s.cipherStateWords)

  # allocate tweak
  s.ubiParameters = initUbiTweak()

proc initSkein*(stateSize, outputSize: int): Skein =
  if stateSize notin {256,512,1024}:
    raiseStateSizeError(stateSize)
  if outputSize <= 0:
    raiseOutputSizeError(outputSize)

  result.setup(stateSize,outputSize)
  result.config = initSkeinConfiguration(result)
  result.config.setSchema(Schema) ## SHA3
  result.config.setVersion(1)
  result.config.generateConfiguration()
  result.initialize()

proc initializeConf(s: var Skein, initType: InitializationType) =
  case initType
  of Normal:
    s.initialize() # Normal initialization
  of ZeroedState:
    copy(s.state, NullStateWords)
  of ChainedState: discard
  of ChainedConfig:
    # generate a chained configuration
    #s.config.generateConfigurationState(s.state)
    s.initialize()

  s.bytesFilled = 0

proc processBlock(s: var Skein, bytes: int) =
  s.cipher.setKey(s.state)
  s.ubiParameters.addBytesProcessed(bytes)
  s.cipher.setTweak(s.ubiParameters.getTweak())

  s.cipher.encrypt(s.state, s.cipherInput)

  # feed-forward input with state
  for i in 0..<len(s.cipherInput):
    s.state[i] = s.state[i] xor s.cipherInput[i]

proc update*(s: var Skein, input: openarray[byte]) =
  # fill input buffer
  for i in 0..<len(input):
    # do a transform if the input buffer is filled
    if s.bytesFilled == s.cipherStateWords*8:
      # copy the input buffer to cipher input buffer
      for i in 0..<s.cipherStateWords:
        s.cipherInput[i] = uint64le(s.inputBuffer,i*8)
      # process the block
      s.processBlock(s.bytesFilled)

      # clear first flag, which will be set
      # by initialize if this is the first transform
      s.ubiParameters.setFirstBlock(false)

      # reset buffer fill count
      s.bytesFilled = 0
    s.inputBuffer[s.bytesFilled] = input[i]
    inc s.bytesFilled

proc updateBits*(s: var Skein, input: openarray[byte], numBits: int) =
  if s.ubiParameters.isBitPad():
    raiseStatusError(0)
  if (numBits+7) div 8 != len(input):
    raiseLengthError(numBits)
  s.update(input)

  # if number of bits is a multiple of bytes
  if (numBits and 0x7) == 0:
    return

  # mask partial bytes and set bitpad flag before doFinal
  var mask = byte(1.uint shl (7.uint - (numBits and 7).uint))
  s.inputBuffer[s.bytesFilled-1] = byte((s.inputBuffer[s.bytesFilled-1] and (0.byte - mask)) or mask)
  s.ubiParameters.setBitPad(true)

proc putBytes(s: var Skein, input: openarray[uint64], output: var openarray[byte], offset, size: int) =
  var j: uint
  for i in 0..<size:
    output[i+offset] = byte(input[(i) div 8] shr j)
    j = (j + 8) and 63

proc finalPad(s: var Skein) =
  # pad leftover space in input buffer with zeros and copy cipher input buffer
  for i in s.bytesFilled..<len(s.inputBuffer):
    s.inputBuffer[i] = 0
  for i in 0..<s.cipherStateWords:
    s.cipherInput[i] = uint64le(s.inputBuffer, i*8)

  # do final message block
  s.ubiParameters.setFinalBlock(true)
  s.processBlock(s.bytesFilled)

proc finalIntern(s: var Skein): seq[byte] =
  # pad leftover space in input buffer with zeros
  # and copy to cipher input buffer
  for i in s.bytesFilled..<len(s.inputBuffer):
    s.inputBuffer[i] = 0
  for i in 0..<s.cipherStateWords:
    s.cipherInput[i] = uint64le(s.inputBuffer, i*8)
  # do final message block
  s.ubiParameters.setFinalBlock(true)
  s.processBlock(s.bytesFilled)

  # clear cipher input
  copy(s.cipherInput, NullStateWords)

  result = newSeq[byte](s.outputBytes)
  var oldState = newSeq[uint64](s.cipherStateWords)

  # save current state of hash to compute output hash
  copy(oldState, s.state)

  var stateBytes = s.cipherStateWords*8
  for i in countup(0,s.outputBytes-1,s.cipherStateWords*8):
    s.ubiParameters.startNewBlockType(Out.uint64)
    s.ubiParameters.setFinalBlock(true)
    s.processBlock(8)

    # output a chunk of the hash
    var outputSize = s.outputBytes - i
    if outputSize > stateBytes:
      outputSize = stateBytes

    # the new state created by processBlock() is (part of) the hash
    #echo "len s.state: ", len(s.state)
    #echo "len result: ", len(result)
    s.putBytes(s.state, result, i, outputSize)

    # restore current state of hash to compute next hash output
    copy(s.state, oldState)

    # increment counter
    inc s.cipherInput[0]

proc doFinal*(s: var Skein): seq[byte] =
  result = s.finalIntern()
  s.reset()

proc initSkeinExtended*(stateSize, outputSize, treeInfo: int, key: openarray[byte]): Skein =
  if stateSize notin {256,512,1024}:
    raiseStateSizeError(stateSize)
  if outputSize <= 0:
    raiseOutputSizeError(outputSize)

  result.setup(stateSize,outputSize)
  if len(key) > 0:
    result.outputBytes = result.cipherStateWords*8
    result.ubiParameters.startNewBlockType(Key.uint64)
    result.update(key)
    result.finalPad()
  result.outputBytes = (outputSize + 7) div 8
  result.config = initSkeinConfiguration(result)
  result.config.setSchema(Schema) ## SHA3
  result.config.setVersion(1)
  
  result.initializeConf(ChainedConfig)

proc skein*(skeinType, hashLength: int, message: openarray[byte]): seq[byte] =
  ## Compute a Skein-`skieinType` (one of 256, 512, or 1024)
  ## Hash length is `hashLength`
  ## Hashes `message` (message length is assumed to be 8 * len(message))
  var skein = initSkein(skeinType, hashLength)
  skein.updateBits(message,len(message)*8)
  result = skein.doFinal()

proc skein*(skeinType, hashLength, messageLength: int, message: openarray[byte]): seq[byte] =
  ## Compute a Skein-`skieinType` (one of 256, 512, or 1024)
  ## Hash length is `hashLength`
  ## Hashes `message`
  ## Allows specification of message length
  var skein = initSkein(skeinType, hashLength)
  skein.updateBits(message,messageLength)
  result = skein.doFinal()

when isMainModule:
  const output256256 = @[0xc8.byte,0x87,0x70,0x87,0xda,0x56,0xe0,0x72,
                      0x87,0x0d,0xaa,0x84,0x3f,0x17,0x6e,0x94,
                      0x53,0x11,0x59,0x29,0x09,0x4c,0x3a,0x40,
                      0xc4,0x63,0xa1,0x96,0xc2,0x9b,0xf7,0xba]
  assert skein(256, 256, []) == output256256

  let msg = newSeq[byte](2048 div 8)

  const output10241024 = @[0x4A.byte, 0xC1, 0x25, 0x1B, 0x3D, 0x81, 0x64, 0x88, 0xC7, 0x81, 0x71, 0xD9, 0x33, 0x18, 0xF1, 0x44,
                          0xC6, 0x96, 0x26, 0x15, 0x29, 0x7F, 0xDD, 0x33, 0x7A, 0xC2, 0x28, 0x80, 0x79, 0x1C, 0x41, 0x90,
                          0x99, 0xF5, 0xF7, 0xA5, 0xFC, 0x8F, 0xF3, 0x80, 0x5C, 0x39, 0x81, 0x02, 0x73, 0x27, 0xCD, 0x8C,
                          0x63, 0x3F, 0x39, 0xA6, 0xFE, 0x2B, 0x5A, 0xEE, 0xE5, 0x15, 0x39, 0x76, 0xA3, 0x6C, 0x90, 0x99,
                          0xF6, 0x00, 0xAE, 0x87, 0x4E, 0x9C, 0x07, 0xE5, 0x7E, 0x15, 0x60, 0xB8, 0xD8, 0xED, 0x91, 0x35,
                          0x26, 0x3E, 0x27, 0xC2, 0x02, 0x7B, 0x5F, 0x71, 0x20, 0xA6, 0x2D, 0xC3, 0x26, 0x67, 0xE1, 0x0B,
                          0x10, 0xE6, 0xFD, 0x23, 0x0B, 0x5B, 0xA1, 0xA4, 0xE0, 0x4E, 0x92, 0xF5, 0x18, 0x2B, 0xBB, 0x57,
                          0x00, 0x80, 0x0B, 0xC2, 0x68, 0x4A, 0x43, 0x9A, 0x78, 0xE0, 0xF9, 0x25, 0xEC, 0xE3, 0xDE, 0x86]
  assert skein(1024, 1024, msg) == output10241024

  const output10241024_2047 = @[111.byte, 254, 63, 184, 78, 203, 209, 9, 23, 216, 113, 60, 101, 
                                238, 153, 228, 174, 93, 186, 29, 194, 136, 176, 167, 10, 39, 
                                177, 134, 192, 139, 10, 131, 205, 206, 174, 35, 92, 201, 4, 
                                149, 186, 187, 214, 231, 219, 31, 210, 98, 213, 203, 50, 231, 
                                39, 138, 159, 54, 61, 254, 50, 78, 227, 226, 195, 81, 24, 233, 
                                20, 223, 23, 190, 6, 26, 217, 151, 114, 52, 229, 245, 16, 143, 
                                28, 71, 190, 187, 135, 140, 241, 38, 202, 105, 138, 96, 220, 234, 
                                163, 145, 100, 18, 195, 253, 60, 255, 99, 234, 110, 76, 104, 16, 
                                177, 225, 201, 197, 115, 202, 64, 159, 120, 224, 31, 243, 65, 12, 
                                36, 70, 69, 234, 43, 27]
  assert skein(1024,1024,2047,msg) == output10241024_2047


ShimSham
========

ShimSham is a [Nim](http://www.nim-lang.org) module to encompass several different digest/hashing algorithms. So far included are
  * [JH](https://en.wikipedia.org/wiki/JH_%28hash_function%29)
  * [SHA-2](https://en.wikipedia.org/wiki/SHA-2)
  * [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
  * [SipHash](http://en.wikipedia.org/wiki/SipHash)
  * [Tiger](https://en.wikipedia.org/wiki/Tiger_%28cryptography%29)
  * [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_%28cryptography%29)

There will be more soon, as well as a common hashing interface.

Using the Tiger hash as an example, here's how you get hashes:
```nim
import shimsham/tiger

echo tiger("") # gives "24f0130c63ac933216166e76b1bb925ff373de2d49584e7a"
echo tiger("abc") # gives "f258c1e88414ab2a527ab541ffc5b8bf935f7b951c132951"
```

The other hashes work in the same way. The *whirlpool* module provides the `whirlpool` function. The *sha512* module provides `sha512` and `sha384`. The *sha256* module provides `sha256` and `sha224`. 

You can get more fine-tuned control with the following type of code:

```nim
import shimsham/sha256

var message = "My message to hash"
var m = initSha256(message) # initializes a `Sha256` object with `message`
echo m # gives "aefd1872a4eb24a79a1e727aa8c41ebde794451c0ca89a0e3abe82e45a477afc"
```
You can also use `initSha224` if that's what you want.

`initSha384` and `initSha512` are available in the sha512 module.

`initWhirlpool` works in the same way.

Unfortunately, the Tiger module doesn't support this yet (it also has some various weird problems, which you'll see if you walk through the code).


SipHash
-------

SipHash works a little differently. It always outputs a hash that Nim treats as a `uint64`. It uses two `uint64` keys for input. You can do this directly using `initSipState(k0,k1)` where `k0` and `k1` are your `uint64`s, or you can input a long hex string directly (like `initSipState("A8FC63780FB3BA3CA39580EEC5CB43B1")`). After you have your state, you can update your message in various ways using `input()`. If you want to use a hex string for your message, too, you can do that.

Really, though, for SipHash, the easiest thing to do is to use the convenience functions `siphash*` where the `*` represents `24` or `48` for SipHash-2-4 and SipHash-4-8 (slower but more secure). Or you can specify your own SipHash-c-d values with `siphash`.

All you need to do then is something like:

```nim
echo siphash24("A8FC63780FB3BA3CA39580EEC5CB43B1","6018B63E6DBF9B") # gives "701bdf2ea1c82585"
```

JH
--

JH is the first SHA-3 finalist to be included here. It is usable by `import`-ing `shimsham/jh_simple`. ("Simple" is a reference to the fact that there could be some assembly support added in the future.)

Skein
-----

Skein is the second SHA-3 finalist to be added to ShimSham. It is also much more complex than most other modules. I haven't yet had time to document all parameters, but this is based off the wonderful [Skein3Fish](https://github.com/wernerd/Skein3Fish), so you can learn more there. The simple function is `skein()`, which takes in different options. For example, to compute a Skein-256, with a hash length of 256, of an empty message, you can do:

```nim
import shimsham/skein

skein(256, 256, []) # @[0xc8.byte,0x87,0x70,0x87,0xda,0x56,0xe0,0x72,
                    #   0x87,0x0d,0xaa,0x84,0x3f,0x17,0x6e,0x94,
                    #   0x53,0x11,0x59,0x29,0x09,0x4c,0x3a,0x40,
                    #   0xc4,0x63,0xa1,0x96,0xc2,0x9b,0xf7,0xba]
```

Since Skein is based off ThreeFish, you get Threefish as a bonus. It's located inside the `skein` directory, but it's not really intended to be part of ShimSham. Nevertheless, if you want, it's there.


ShimSham
========

ShimSham is a Nim module to encompass several different digest/hashing algorithms. So far included are [SHA-2](https://en.wikipedia.org/wiki/SHA-2), [Tiger](https://en.wikipedia.org/wiki/Tiger_%28cryptography%29), [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_%28cryptography%29), and [SipHash](http://en.wikipedia.org/wiki/SipHash). Hopefully there will be some more soon.

Unfortunately, there isn't a common hashing interface yet.

For the Tiger hash, here's how you call:
```nim
import tiger

echo tiger("") # gives "24f0130c63ac933216166e76b1bb925ff373de2d49584e7a"
echo tiger("abc") # gives "f258c1e88414ab2a527ab541ffc5b8bf935f7b951c132951"
```

The other hashes work in the same way. The *whirlpool* module provides the `whirlpool` function. The *sha512* module provides `sha512` and `sha384`. The *sha256* module provides `sha256` and `sha224`. 

You can get more fine-tuned control with the following type of code:

```nim
import sha256

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
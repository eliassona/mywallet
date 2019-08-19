# mywallet

Implementation of BIP-39 and BIP-32

## Usage

### BIP-39

The first step is to create the mnemonic. Here are some examples.
```clojure
(use 'mywallet.bip39)
=> (entropy->mnemonic "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
("legal" "winner" "thank" "year" "wave" "sausage" "worth" "useful" "legal" "winner" "thank" "year" "wave" "sausage" "worth" "useful" "legal" "will")

=> (entropy->mnemonic "00000000000000000000000000000000")
("abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "about")


```

Now that we have the mnemonic. We can generate the seed.

```clojure
(mnemonic->seed (clojure.string/join " " ["abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "abandon" "about"]) "mypw") 
"a086058f4cab51b92457de2c3bcf8bef1d8bda4c3558d56caec949c47f7f858b3585a9a23dedd577952c2af3f65efdaaa1db4dff47ceea0079f5d8ec49f42e3d"

(mnemonic->seed (clojure.string/join " " ["legal" "winner" "thank" "year" "wave" "sausage" "worth" "useful" "legal" "winner" "thank" "year" "wave" "sausage" "worth" "useful" "legal" "will"]) "mypw")
"62468fcb06d3283d3ee51384b24387399ee1491333b7fd8f5a453d824109f2c50f0cb0e8bd612e50a2fdbaa755a0d1b1c9a18f75371d1a0b4d600696678a24cc"

```

### BIP-32



FIXME

## License

Copyright © 2019 FIXME

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.

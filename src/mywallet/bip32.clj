(ns ^{:doc "Implementation of BIP32. https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki"} 
    mywallet.bip32
  (:require [mywallet.core :refer :all])
  (:import [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]
           [org.bouncycastle.asn1.sec SECNamedCurves]
           [org.bouncycastle.crypto.params ECDomainParameters] 
           [org.bouncycastle.math.ec ECPoint$Fp]))

(def bitcoin-seed (.getBytes "Bitcoin seed"))

(def curve (SECNamedCurves/getByName "secp256k1"))

(def domain (ECDomainParameters. (.getCurve curve) (.getG curve) (.getN curve) (.getH curve)))

(def version-map {:mainnet {:public 0x0488B21E, :private 0x0488ADE4}, :testnet {:public 0x043587CF, :private 0x04358394}}) 

(def mac (Mac/getInstance "HmacSHA512"))


(defn check-master-key [l]
  (when  (>= (.compareTo l (.getN curve)) 0)
		(throw (IllegalStateException. "Error"))))

(defn ba-copy-range [ba start-ix size]
  (let [dest-ba (byte-array size)]
    (System/arraycopy ba start-ix dest-ba 0 size)
    dest-ba))


(defn pub-key-of [prv-key]
  (let [q (-> curve .getG (.multiply prv-key))]
    (.getEncoded (ECPoint$Fp. (.getCurve domain) (.getX q) (.getY q) true))))

(defn master-key-pair-of [p]
  (let [prv-key (.mod (BigInteger. 1, p) (.getN curve ))]
    {:prv prv-key
     :pub (pub-key-of prv-key)}))
  

(defn master-keypair-of [seed]
  (let [
        seedkey (SecretKeySpec. bitcoin-seed "HmacSHA512")
        _ (.init mac seedkey)
        lr (.doFinal mac seed)
        _ (-> lr vec count dbg)
        l (ba-copy-range lr 0 32)
        r (ba-copy-range lr 32 32)
        _  (check-master-key (BigInteger. 1, l))
        ]
    (master-key-pair-of l)
   ))

(defn child-key-of [extended-key]
  )


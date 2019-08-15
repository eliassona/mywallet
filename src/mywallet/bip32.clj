(ns ^{:doc "Implementation of BIP32. https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki"} 
    mywallet.bip32
  (:require [mywallet.core :refer :all])
  (:import [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]
           [org.bouncycastle.asn1.sec SECNamedCurves]
           [org.bouncycastle.crypto.params ECDomainParameters]
           [org.bouncycastle.crypto.digests RIPEMD160Digest]
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

(defn master-key-pair-of [lr]
  (let [l (:l lr)]
    {:prv l
     :pub (pub-key-of (.mod (BigInteger. 1, l) (.getN curve )))
     :chain (:r lr)}))
  

(defn mac-sha-512 [ba]
  (let [seed-key (SecretKeySpec. bitcoin-seed "HmacSHA512")]
    (.init mac seed-key)
    (.doFinal mac ba)))

(defn split-l-r [ba]
  {:l (ba-copy-range ba 0 32)
   :r (ba-copy-range ba 32 32)})
  

(defn derive-master-key-pair [seed]
  (let [lr (-> seed mac-sha-512 split-l-r)
        _  (check-master-key (BigInteger. 1, (:l lr)))]
    (master-key-pair-of lr)))

(defn ser-32 [v]
  (reverse (map (fn [i] (bit-and (bit-shift-right v (* 8 i)) 0xff)) (range 4))))

(defn derive-child-key-pair [parent-key-pair index]
  (let [lr (split-l-r (mac-sha-512 (byte-array (concat (:pub parent-key-pair)  (:chain parent-key-pair) (ser-32 index)))))
        child-private-key (.add (BigInteger. (:prv parent-key-pair)) (BigInteger. (:l lr)))
        child-public-key (pub-key-of child-private-key)]
    {:pub child-public-key, :prv child-private-key, :chain (:r lr)}))


(defn derive-public-child-key [parent-pub-key parent-chain-code index]
  (let [lr (split-l-r (mac-sha-512 (byte-array (concat parent-pub-key  parent-chain-code (ser-32 index)))))]
    {:pub (.toByteArray (.add (BigInteger. parent-pub-key) (BigInteger. (pub-key-of (BigInteger. (:l lr)))))), :chain (:r lr)}))


(ns ^{:doc "Implementation of BIP32. https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki"} 
    mywallet.bip32
  (:require [mywallet.core :refer :all])
  (:import [java.security Security]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]
           [org.bouncycastle.asn1.sec SECNamedCurves]
           [org.bouncycastle.crypto.params ECDomainParameters]
           [org.bouncycastle.crypto.digests RIPEMD160Digest]
           [org.bouncycastle.math.ec ECPoint$Fp]
           [mywallet ByteUtil ExtendedKey ECKey Hash]))

(Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(def bitcoin-seed (.getBytes "Bitcoin seed"))

(def curve (SECNamedCurves/getByName "secp256k1"))

(def domain (ECDomainParameters. (.getCurve curve) (.getG curve) (.getN curve) (.getH curve)))

(def version-map {:mainnet {:pub 0x0488B21E, :prv 0x0488ADE4}, :testnet {:pub 0x043587CF, :prv 0x04358394}}) 

(def hardened-child 0x80000000)

(defn private? [version]
  (or 
    (= (-> version-map :mainnet :prv) version)
    (= (-> version-map :testnet :prv) version)))
  

(def mac (Mac/getInstance "HmacSHA512" "BC"))


(defn extended-key-hash-of [key]
  (let [ph (byte-array 20)
        sha256 (calc-sha-256 key)
        digest (RIPEMD160Digest.)]
    (.update digest sha256 0 (count sha256))
    (.doFinal digest ph 0)
    ph))



(defn check-master-key [l]
  (when  (>= (.compareTo l (.getN curve)) 0)
		(throw (IllegalStateException. "Error"))))

(defn ba-copy-range [ba start-ix size]
  (let [dest-ba (byte-array size)]
    (System/arraycopy ba start-ix dest-ba 0 size)
    dest-ba))


(defn pub-key-of [prv-key]
  (.getEncoded (.multiply (.getG curve) prv-key) true)
  #_(-> curve .getG (.multiply prv-key) .getEncoded)
  #_(let [q (-> curve .getG (.multiply prv-key))]
     (.getEncoded (ECPoint$Fp. (.getCurve domain) (.getX q) (.getY q) true))))

(defn master-key-pair-of [lr]
  (let [l (:l lr)]
    {:prv l
     :pub (pub-key-of (.mod (BigInteger. 1, l) (.getN curve )))
     :chain (:r lr)}))
  

(defn mac-sha-512 
  ([ba key]
  (let [seed-key (SecretKeySpec. key "HmacSHA512")]
    (.init mac seed-key)
    (.doFinal mac ba)))
  ([ba]
    (mac-sha-512 ba bitcoin-seed)))
    

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
  (let [mac-fn (partial mac-sha-512 (:chain parent-key-pair))
        lr (-> (concat (:pub parent-key-pair) (ser-32 index))  
                byte-array 
                mac-fn 
                split-l-r)
        child-private-key (.mod (.add (BigInteger. 1 (:l lr)) (BigInteger. 1 (:prv parent-key-pair))) (.getN curve))
        child-public-key (pub-key-of child-private-key)]
    {:pub child-public-key, :prv (.toByteArray child-private-key), :chain (:r lr)}))


(defn derive-public-child-key [parent-pub-key parent-chain-code index]
  (let [lr (split-l-r (mac-sha-512 
                        (byte-array (concat parent-pub-key  (ser-32 index))) 
                        parent-chain-code))]
    {:pub (.toByteArray (.add (BigInteger. 1 parent-pub-key) (BigInteger. 1 (pub-key-of (BigInteger. 1 (:l lr)))))), :chain (:r lr)}))



(defn extend-key-format-of [version 
                            depth 
                            parent-fingerprint 
                            index
                            chain-code
                            key-bytes
                            ]
  (let [ba (byte-array 
      (concat
        (ser-32 version)
        [(bit-and depth 0xff)]
        parent-fingerprint
        (ser-32 index)
        chain-code
        ;(if (private? version) [0] [])
        key-bytes))]
    (-> ba vec dbg)
    (ByteUtil/toBase58WithChecksum 
      ba)))


[4 -120 -83 -28 1 -67 22 -66 -27 0 0 0 0 -16 -112 -102 -1 -86 126 -25 -85 -27 -35 78 16 5 -104 -44 -36 83 -51 112 -99 90 92 44 -84 64 -25 65 47 35 47 124 -100 0 -85 -25 74 -104 -10 -57 -22 -66 -32 66 -113 83 121 -113 10 -72 -86 27 -45 120 115 -103 -112 65 112 60 116 47 21 -84 126 30] 
[4 -120 -83 -28 1 -67 22 -66 -27 0 0 0 0 -16 -112 -102 -1 -86 126 -25 -85 -27 -35 78 16 5 -104 -44 -36 83 -51 112 -99 90 92 44 -84 64 -25 65 47 35 47 124 -100 0 0 -85 -25 74 -104 -10 -57 -22 -66 -32 66 -113 83 121 -113 10 -72 -86 27 -45 120 115 -103 -112 65 112 60 116 47 21 -84 126 30]

(defn fp-kp-of [kp] 
  (let [fp (->> kp :pub extended-key-hash-of (take 4) byte-array)]
    fp))

(defn kp-map-of [ext-fn] (into {} (map (fn [k] [k (ext-fn k)]) [:prv :pub])))

(defn parse-index [s]
  (if (.endsWith s "H")
    (bit-or (Integer/decode (.substring s 0 (dec (count s)))) hardened-child) 
    (Integer/decode s)))


(defn point-ser [k]
  (.getEncoded (.multiply (.getG curve) k) true))

(defn hardened-child-concat [k i]
  (byte-array (concat [0] k (ser-32 i))))

(defn normal-child-concat [k i]
  #_(byte-array (concat k (ser-32 i)))
  (byte-array (concat (point-ser (BigInteger. 1 k)) (ser-32 i))))


(defn ckd-priv [k c i]
    (let [lr (split-l-r 
               (mac-sha-512 
                (if (>= i hardened-child) 
                  (hardened-child-concat k i)
                  (normal-child-concat k i))
                c))]
      {:chain (:r lr), :prv (.toByteArray (.mod (.add (BigInteger. 1 (:l lr)) (BigInteger. 1 k)) (.getN curve)))}))



(defn extended-key-pair-of 
  ([seed path]
    (let [root-fp (byte-array [0 0 0 0])
          mk (derive-master-key-pair (hex-str->ba seed))]
        (extended-key-pair-of 
          (ExtendedKey. (:chain mk) 0 0 0 (ECKey. (:prv mk) true)) 0 (.split path "/")) 
        #_(extended-key-pair-of  mk 0 0 (.split path "/") root-fp)))
  ([parent depth index path fp]
    (let [net (:mainnet version-map)] 
     (if (>= depth (dec (count path)))
       (let [ext-fn (fn [k] (extend-key-format-of (k net) depth fp index (:chain parent) (k parent)))]
         (kp-map-of ext-fn))
       (let [depth (inc depth)
             index (parse-index (nth path depth))]
         (extended-key-pair-of (ckd-priv (:prv parent) (:chain parent) index) depth index path (fp-kp-of parent))))))
 ([ek depth path]
    (if (>= depth (dec (count path)))
      {:prv (.serializePrivate ek), :pub (.serializePublic ek)}
      (let [depth (inc depth)
            index (parse-index (nth path depth))]
        (extended-key-pair-of (.derive ek index) depth path))))
    
  )




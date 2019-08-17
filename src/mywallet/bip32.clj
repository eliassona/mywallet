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
           [mywallet ByteUtil ExtendedKey ECKey]))

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
  (ByteUtil/toBase58WithChecksum 
    (byte-array 
      (concat
        (ser-32 version)
        [(bit-and depth 0xff)]
        parent-fingerprint
        (ser-32 index)
        chain-code
        (if (private? version) [0] [])
        key-bytes))))

(defn fp-kp-of [kp] 
  (let [fp (->> kp :pub extended-key-hash-of (take 4) byte-array)]
    fp))

(defn kp-map-of [ext-fn] (into {} (map (fn [k] [k (ext-fn k)]) [:prv :pub])))

(defn parse-index [s]
  (if (.endsWith s "H")
    {:hardened true, :value (Integer/decode (.substring s 0 (dec (count s))))}
    {:hardened false, :value (Integer/decode s)}))

(defn extended-key-pair-of 
  ([seed path]
    (let [root-fp (byte-array [0 0 0 0])
          mk (derive-master-key-pair (hex-str->ba seed))]
        (extended-key-pair-of 
          (ExtendedKey. (:chain mk) 0 0 0 (ECKey. (:prv mk) true)) 0 (.split path "/"))))
  ([kp depth index path fp]
    #_(let [net (:mainnet version-map)] 
       (if (>= depth (dec (count path)))
         (let [ext-fn (fn [k] (extend-key-format-of (k net) depth fp index (:chain kp) (k kp)))]
           (kp-map-of ext-fn))
         (let [depth (inc depth)
               index (Integer/decode (nth path depth))]
           (extended-key-pair-of 
             (derive-child-key-pair kp index) depth index path (fp-kp-of kp))))))
  ([ek depth path]
    (if (>= depth (dec (count path)))
      {:prv (.serializePrivate ek), :pub (.serializePublic ek)}
      (let [depth (inc depth)
            index (parse-index (nth path depth))]
        (extended-key-pair-of (.derive ek (:value index), (:hardened index)) depth path))))
    
  )


(defn point-ser [k]
  (.getEncoded (.multiply (.getG curve) k) true))

(defn hardened-child-concat [k i]
  (byte-array (concat [0] k (ser-32 i))))

(defn normal-child-concat [k i]
  (byte-array (concat (point-ser (BigInteger. 1 k)) (ser-32 i))))


(defn CKDpriv [k c i]
    (split-l-r 
      (mac-sha-512 
       (if (>= i hardened-child) 
         (hardened-child-concat k i)
         (normal-child-concat k i))
       c)))
  

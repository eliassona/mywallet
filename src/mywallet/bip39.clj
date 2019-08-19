(ns ^{:doc "Implementation of BIP39. https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki"} 
    mywallet.bip39
  (:require [mywallet.core :refer :all]
            [clojure.string :refer [join]])
  (:import [java.net HttpURLConnection URL]
           [java.security MessageDigest]
           [javax.crypto SecretKeyFactory]
           [javax.crypto.spec PBEKeySpec]
           [java.text Normalizer Normalizer$Form]))

(defonce word-list (vec (.split (url-get "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt") "\n")))

(defn calc-word-list-hash []
  (ba->hex-str (calc-sha-256 (.getBytes (apply str word-list) "UTF-8"))))

(def word-list-hash "ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db")

(when 
  (not= word-list-hash (calc-word-list-hash))
  (throw (IllegalStateException. "word list has changed, DANGER!!!!!")))

(defonce word->index-map 
  (into {} (map-indexed (fn [i v] [v i]) word-list)))

(def cs-mod 32)
(def nr-of-bits-in-group 11)

(defn correct-bits? [n]
  (when (or (< n 128) (not= (mod n cs-mod) 0))
    (throw (IllegalArgumentException. "Incorrect number of bits"))))

(defn calc-hash [entropy-ba cs]
  (-> entropy-ba
      calc-sha-256
      first
      (bit-and 0xff)
      (bit-shift-right (- 8 cs))))
  
(defn entropy->mnemonic [entropy]
  (let [entropy (hex-str->ba entropy)
        nr-of-bits (* (count entropy) 8)
        _ (correct-bits? nr-of-bits)
        cs (/ nr-of-bits cs-mod)
        hash (calc-hash entropy cs)]
    (->> 
      (str (ba->bin-str entropy) (pad-bits cs (Integer/toBinaryString hash))) 
      (partition-all nr-of-bits-in-group)
      (map (comp (partial nth word-list) #(Integer/parseInt % 2) (partial apply str))))))

(defn normalize [s] (Normalizer/normalize s, Normalizer$Form/NFKD))

(def iterations 2048)
(def derivation-seed-bitsize 512)

(defn str-of [mnemonic]
  (if (instance? String mnemonic)
    mnemonic
    (clojure.string/join " " mnemonic)))

(defn mnemonic->seed [mnemonic salt]
  (let [spec (PBEKeySpec. (.toCharArray (normalize (str-of mnemonic))) (.getBytes (str "mnemonic" (normalize salt)) "UTF-8") iterations derivation-seed-bitsize)
        skf  (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA512")] 
    (ba->hex-str (.getEncoded (.generateSecret skf spec)))))



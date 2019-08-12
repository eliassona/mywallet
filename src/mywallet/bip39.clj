(ns mywallet.bip39
  (:import [java.net HttpURLConnection URL]
           [java.security MessageDigest])
  )
(defmacro dbg [body]
  `(let [x# ~body]
     (println "dbg:" '~body "=" x#)
     x#))

(def word-list-url "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt")


(def sha-256 (MessageDigest/getInstance "SHA-256"))

(def zero-bit (constantly "0"))

(defn pad-bits [n bit-str] (str (apply str (map zero-bit (range (- n (count bit-str))))) bit-str))

(defn ba->bin-str [ba]
  (apply str (map (comp (partial pad-bits 8) #(Integer/toBinaryString (bit-and 0xff %))) ba)))

(defn ba->hex-str [ba]
  (apply str (map #(Integer/toHexString (bit-and 0xff %)) ba))) 

(defn calc-sha-256 [data]
  (.reset sha-256)
  (.digest sha-256 data))

(def word-list 
  (let [con (.openConnection (URL. word-list-url))
        _ (.setRequestMethod con "GET")
        in (.getInputStream con)]
    (vec (.split (slurp in) "\n"))
    )
  )

(def word->index-map 
  (into {} (map-indexed (fn [i v] [v i]) word-list)))

(def cs-mod 32)

(defn correct-bits? [n]
  (when 
    (or 
      (< n 128)
      (not= (mod n cs-mod) 0))
    (throw (IllegalArgumentException. "Incorrect number of bits"))))


(defn calc-hash [entropy-ba cs]
  (let [hash-bits (int (- (Math/pow 2 cs) 1))]
    (bit-and (.longValue (BigInteger. (calc-sha-256 entropy-ba))) hash-bits)))
   
  

(defn entropy->mnemonic [entropy-ba]
  (let [nr-of-bits (* (count entropy-ba) 8)
        _ (correct-bits? nr-of-bits)
        cs (/ nr-of-bits cs-mod)
        hash-bits (int (- (Math/pow 2 cs) 1))
        hash (byte (calc-hash entropy-ba cs))]
    (ba->bin-str (concat entropy-ba [hash]))
  ))


(defn binary->hex [bin-str]
  )


(def bin->hex-map {"0000" "0", "0001" "1", "0010" "2", "0011", "3"
                   "0100" "4", "0101" "5", "0110" "6", "0111", "7"
                   "1000" "8", "1001" "9", "1010" "a", "1011", "b"
                   "1100" "c", "1101" "d", "1110" "e", "1111", "f"})

(defn passphrase->pk [words] 
  (->> 
    (map (comp (partial pad-bits 11) #(Integer/toBinaryString %) word->index-map) words) 
    (apply str)
    (partition-all 4)
    (map (partial apply str))
    (map bin->hex-map)
    (apply str)))
  

(ns mywallet.bip39
  (:import [java.net HttpURLConnection URL]
           [java.security MessageDigest])
  )
(defmacro dbg [body]
  `(let [x# ~body]
     (println "dbg:" '~body "=" x#)
     x#))

(def sha-256 (MessageDigest/getInstance "SHA-256"))

(defn calc-sha-256 [data]
  (.reset sha-256)
  (.digest sha-256 data))

(def zero-bit (constantly "0"))

(defn pad-bits [n bit-str] (str (apply str (map zero-bit (range (- n (count bit-str))))) bit-str))

(defn ba->bin-str [ba]
  (apply str (map (comp (partial pad-bits 8) #(Integer/toBinaryString (bit-and 0xff %))) ba)))

(defn ba->hex-str [ba]
  (apply str (map (comp (partial pad-bits 2) #(Integer/toHexString (bit-and 0xff %))) ba))) 

(def word-list-url "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt")

(defn url-get [url]
  (let [con (.openConnection (URL. url))
        _ (.setRequestMethod con "GET")
        in (.getInputStream con)
        ]
    (try
      (slurp in)
      (finally (.close in)))))

(defonce word-list (vec (.split (url-get word-list-url) "\n")))

(defonce word->index-map 
  (into {} (map-indexed (fn [i v] [v i]) word-list)))

(def cs-mod 32)
(def nr-of-bits-in-group 11)

(defn correct-bits? [n]
  (when 
    (or 
      (< n 128)
      (not= (mod n cs-mod) 0))
    (throw (IllegalArgumentException. "Incorrect number of bits"))))


(defn calc-hash [entropy-ba cs]
  (bit-shift-right (bit-and 0xff (first (calc-sha-256 entropy-ba))) (- 8 cs)))
   


(defn hex-str->ba [hex-str]
  (if (instance? String hex-str)
    (->> hex-str
      (partition-all 2)
      (map (comp #(Integer/decode %) (partial str "0x") (partial apply str)))
      byte-array
      )
    
    hex-str))
  

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


(def bin->hex-map {"0000" "0", "0001" "1", "0010" "2", "0011", "3"
                   "0100" "4", "0101" "5", "0110" "6", "0111", "7"
                   "1000" "8", "1001" "9", "1010" "a", "1011", "b"
                   "1100" "c", "1101" "d", "1110" "e", "1111", "f"})


  

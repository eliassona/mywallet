(ns mywallet.core
  (:import [java.net HttpURLConnection URL]
           [java.security MessageDigest]))

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

(defn hex-str->ba [hex-str]
  (if (instance? String hex-str)
    (->> hex-str
      (partition-all 2)
      (map (comp #(Integer/decode %) (partial str "0x") (partial apply str)))
      byte-array)
    hex-str))

(defn url-get [url]
  (let [con (.openConnection (URL. url))
        _ (.setRequestMethod con "GET")
        in (.getInputStream con)
        ]
    (try
      (slurp in)
      (finally (.close in)))))


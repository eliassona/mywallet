(ns mywallet.bip39_test
  (:require [clojure.test :refer :all]
            [mywallet.core :refer :all]
            [mywallet.bip39 :refer :all]
            [clojure.data.json :as json]))


(defonce test-vectors (get (->> "https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json" url-get json/read-str) "english")) 

(defn verify-test-vector [[entropy mnemonic seed pk]]
  (let [mnemonics-list (entropy->mnemonic entropy)
        actual-mnemonics (clojure.string/join " " mnemonics-list)]
    (is (= mnemonic actual-mnemonics))
    (is (= seed (mnemonic->seed actual-mnemonics "TREZOR")))
    (is (= entropy (mnemonic->entropy mnemonics-list)))))

(deftest verify-test-vectors 
  (doseq [tv test-vectors]
    (verify-test-vector tv)))


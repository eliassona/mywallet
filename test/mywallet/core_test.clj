(ns mywallet.core-test
  (:require [clojure.test :refer :all]
            [mywallet.core :refer :all]))

(deftest verify-pad-bits
  (is (= "00000010" (pad-bits 8 "10")))
  (is (= "11111111" (pad-bits 8 "11111111")))
  (is (= "00000000" (pad-bits 8 "")))
  (is (= "0010" (pad-bits 4 "10")))
  )

(deftest verify-ba->bin-str 
  (is (= "00000001000000100000001100000100" (ba->bin-str (byte-array [1 2 3 4]))))
  )

(deftest verify-ba->hex-str
  (is (= "ff0f0304" (ba->hex-str (byte-array [255 15 3 4]))))
  (is (= "00000000000000000000000000000000" (ba->hex-str (byte-array [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]))))
  )

(deftest verify-hex-str->ba
  (is (= (vec (byte-array [255 15 3 4])) (vec (hex-str->ba "ff0f0304"))))
  (is (= (vec (byte-array [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0])) (vec (hex-str->ba "00000000000000000000000000000000"))))
  )


(defmodule tut13
  (export (format-temps 1)))

(defun format-temps (cities)
  (let* ((converted (->c cities)))
    (print-temps converted)
    (print-max-min (find-max-min converted))))

(defun ->c
  (((cons (tuple name (tuple 'F temp)) tail))
   (let ((converted (tuple name (tuple 'C (/ (* (- temp 32) 5) 9)))))
     (cons converted (->c tail))))
  (((cons city tail))
   (cons city (->c tail)))
  (('())
   '()))

(defun print-temps
  (((cons (tuple name (tuple 'C temp)) tail))
   (io:format "~-15w ~w c~n" (list name temp))
   (print-temps tail))
  (('())
   'ok))

(defun find-max-min
  (((cons city tail))
    (find-max-min tail city city)))

(defun find-max-min
  (((cons head tail) max-city min-city)
   (find-max-min tail
                 (compare-max head max-city)
                 (compare-min head min-city)))
  (('() max-city min-city)
   (tuple max-city min-city)))

(defun compare-max
  (((= (tuple name1 (tuple 'C temp1)) city1)
    (= (tuple name2 (tuple 'C temp2)) city2))
   (if (> temp1 temp2)
     city1
     city2)))

(defun compare-min
  (((= (tuple name1 (tuple 'C temp1)) city1)
    (= (tuple name2 (tuple 'C temp2)) city2))
   (if (< temp1 temp2)
     city1
     city2)))

(defun print-max-min
  (((tuple (tuple max-name (tuple 'C max-temp))
           (tuple min-name (tuple 'C min-temp))))
   (io:format "Max temperature was ~w c in ~w~n" (list max-temp max-name))
   (io:format "Min temperature was ~w c in ~w~n" (list min-temp min-name)))
)

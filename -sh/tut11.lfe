(defmodule tut11
  (export (format-temps 1)))

(defun format-temps (cities)
  (->c cities))

(defun ->c
  (((cons (tuple name (tuple 'F temp)) tail))
   (let ((converted (tuple name (tuple 'C (/ (* (- temp 32) 5) 9)))))
     (cons converted (->c tail))))
  (((cons city tail))
   (cons city (->c tail)))
  (('())
   '()))

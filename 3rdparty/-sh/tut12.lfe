(defmodule tut12
  (export (format-temps 1)))

(defun format-temps (cities)
  (print-temps (->c cities)))

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

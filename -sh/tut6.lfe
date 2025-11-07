(defmodule tut6
  (export (list-length 1)))

(defun list-length
  ([()] 0)
  ([(cons first rest)]
   (+ 1 (list-length rest))))

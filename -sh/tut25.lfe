(defmodule tut25
  (export (demo 0)))

(defun demo ()
  (loop '(1 2 3 4 5)))

(defun loop
  ([()] 'done)
  ([(cons 3 rest)]
   (loop rest))
  ([(cons n rest)]
   (lfe_io:format "~p" (list n))
   (loop rest)))


(defmodule tut18
  (export (start 0) (say-something 2)))

(defun say-something
  ([what 0] 'done)
  ([what times]
   (lfe_io:format "~p~n" (list what))
   (say-something what (- times 1))))

(defun start ()
  (spawn 'tut18 'say-something '(hello 3))
  (spawn 'tut18 'say-something '(goodbye 3)))

(defmodule tut10
  (export all))

(defun reverse (list)
  (reverse list '()))

(defun reverse
  (((cons head tail) reversed-list)
   (reverse tail (cons head reversed-list)))
  (('() reversed-list)
   reversed-list))

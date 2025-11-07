(defmodule tut24
  (export (demo 0)))

(defrecord message-to to-name message)

(defun demo ()
  (let ((msg (make-message-to message "hello" to-name 'fred)))
    (case msg
      ((match-message-to to-name name message text)
       (lfe_io:format "to ~p: ~p~n" (list name text))))
    (let ((msg2 (set-message-to-message msg "goodbye")))
      (message-to-message msg2))))

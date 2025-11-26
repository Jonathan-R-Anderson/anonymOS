(defmodule tut19
  (export (start 0) (ping 2) (pong 0)))

(defun ping
  ((0 pong-pid)
   (! pong-pid 'finished)
   (lfe_io:format "Ping finished~n" ()))
  ((n pong-pid)
   (! pong-pid (tuple 'ping (self)))
   (receive
     ('pong (lfe_io:format "Ping received pong~n" ())))
   (ping (- n 1) pong-pid)))

(defun pong ()
  (receive
    ('finished
     (lfe_io:format "Pong finished~n" ()))
    ((tuple 'ping ping-pid)
     (lfe_io:format "Pong received ping~n" ())
     (! ping-pid 'pong)
     (pong))))

(defun start ()
  (let ((pong-pid (spawn 'tut19 'pong ())))
    (spawn 'tut19 'ping (list 3 pong-pid))))

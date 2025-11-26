(defmodule tut23
  (export (start-ping 1) (start-pong 0) (ping 2) (pong 0)))

(defun ping
  ((0 pong-node)
   (lfe_io:format "Ping finished~n" ()))
  ((n pong-node)
   (! (tuple 'pong pong-node) (tuple 'ping (self)))
   (receive
     ('pong (lfe_io:format "Ping received pong~n" ())))
   (ping (- n 1) pong-node)))

(defun pong ()
  (receive
    ((tuple 'ping ping-pid)
     (lfe_io:format "Pong received ping~n" ())
     (! ping-pid 'pong)
     (pong))
    (after 5000
      (lfe_io:format "Pong timed out~n" ()))))

(defun start-pong ()
  (register 'pong (spawn 'tut23 'pong ())))

(defun start-ping (pong-node)
  (spawn 'tut23 'ping (list 3 pong-node)))

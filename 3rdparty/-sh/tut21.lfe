(defmodule tut21
  (export (start 1) (ping 2) (pong 0)))

(defun ping (n pong-pid)
  (link pong-pid)
  (ping1 n pong-pid))

(defun ping1
  ((0 pong-pid)
   (exit 'ping))
  ((n pong-pid)
   (! pong-pid (tuple 'ping (self)))
   (receive
     ('pong (lfe_io:format "Ping received pong~n" ())))
   (ping1 (- n 1) pong-pid)))

(defun pong ()
  (process_flag 'trap_exit 'true)
  (pong1))

(defun pong1 ()
  (receive
    ((tuple 'ping ping-pid)
     (lfe_io:format "Pong received ping~n" ())
     (! ping-pid 'pong)
     (pong1))
    ((tuple 'EXIT from reason)
     (lfe_io:format "Pong exiting, got ~p~n" (list (tuple 'EXIT from reason))))))

(defun start (ping-node)
  (let ((pong-pid (spawn 'tut21 'pong ())))
    (spawn ping-node 'tut21 'ping (list 3 pong-pid))))

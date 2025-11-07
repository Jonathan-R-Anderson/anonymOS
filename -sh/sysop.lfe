(defmodule sysop
  "Command line entry point for the sysop provisioning tool."
  (export (main 1)
          (handle 1)))

(defun main (argv)
  (let ((result (catch (handle argv))))
    (case result
      ((tuple 'ok plan)
       (let ((payload (sysop-json:encode (sysop-schemas:creation-plan->map plan))))
         (io:format "~s~n" (list payload))
         0))
      ((tuple 'error reason)
       (io:format "error: ~p~n" (list reason))
       1)
      (_
       (io:format "error: unexpected~n" '())
       1))))

(defun handle (argv)
  (case argv
    ((cons "user" (cons "add" rest)) (handle-user-add rest))
    (_ (tuple 'error 'unsupported_command))))

(defun handle-user-add (args)
  (let* ((opts (parse-options args '()))
         (username (get-option 'username opts))
         (fs (get-option 'fs opts))
         (request (sysop-schemas:build-create-user-request username fs))
         (plan (sysop-users:create_user request)))
    (tuple 'ok plan)))

(defun parse-options
  (('() opts) opts)
  (((cons "--username" (cons value rest)) opts)
   (parse-options rest (lists:keystore 'username 1 opts (tuple 'username value))))
  (((cons "--fs" (cons value rest)) opts)
   (parse-options rest (lists:keystore 'fs 1 opts (tuple 'fs value))))
  (((cons _ _) _) (tuple 'error 'invalid_option)))

(defun get-option (key opts)
  (case opts
    ((tuple 'error reason) (erlang:error reason))
    (_
     (case (lists:keyfind key 1 opts)
       ((tuple _ value) value)
       (_ (erlang:error (tuple 'missing_option key)))))))

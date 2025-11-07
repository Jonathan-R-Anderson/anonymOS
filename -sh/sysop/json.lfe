(defmodule sysop-json
  "Minimal JSON encoder for sysop data structures."
  (export (encode 1)))

(defun encode (value)
  (cond ((erlang:is_integer value) (integer_to_list value))
        ((erlang:is_float value) (float-to-string value))
        ((erlang:is_atom value) (encode-atom value))
        ((erlang:is_tuple value) (encode (tuple_to_list value)))
        ((erlang:is_list value) (encode-list value))
        (true (encode-string (lists:flatten (io_lib:format "~p" (list value)))))))

(defun float-to-string (value)
  (lists:flatten (io_lib:format "~.16g" (list value))))

(defun encode-atom (value)
  (case value
    ('true "true")
    ('false "false")
    ('null "null")
    (_ (encode-string (atom_to_list value)))))

(defun encode-list (value)
  (cond ((=:= value '()) "[]")
        ((object-list? value) (encode-object value))
        ((string? value) (encode-string value))
        (true (encode-array value))))

(defun encode-object (pairs)
  (let* ((encoded (lists:map #'encode-pair/1 pairs))
         (body (string:join encoded ",")))
    (lists:flatten (io_lib:format "{~s}" (list body))))

(defun encode-pair (pair)
  (case pair
    ((tuple key value)
     (let ((key-str (encode-string (ensure-string key)))
           (val (encode value)))
       (lists:flatten (io_lib:format "~s:~s" (list key-str val)))))
    (_ (encode pair))))

(defun encode-array (items)
  (let* ((encoded (lists:map #'encode/1 items))
         (body (string:join encoded ",")))
    (lists:flatten (io_lib:format "[~s]" (list body))))

(defun encode-string (value)
  (let ((escaped (escape-chars value)))
    (lists:flatten (io_lib:format "\"~s\"" (list escaped)))))

(defun escape-chars (value)
  (lists:flatten (escape-chars-acc value '())))

(defun escape-chars-acc
  (('() acc) (lists:reverse acc))
  (((cons char rest) acc)
   (escape-chars-acc rest (cons (escape-char char) acc))))

(defun escape-char (char)
  (case char
    (#\" "\\\"")
    (#\\ "\\\\")
    (#\b "\\b")
    (#\f "\\f")
    (#\n "\\n")
    (#\r "\\r")
    (#\t "\\t")
    (_ (list char))))

(defun object-list? (value)
  (case value
    ('() 'false)
    ((cons head tail)
     (andalso (tuple-keypair? head)
              (or (=:= tail '()) (object-list? tail))))
    (_ 'false)))

(defun tuple-keypair? (value)
  (andalso (erlang:is_tuple value)
           (=:= (erlang:tuple_size value) 2)
           (key-type? (element 1 value))))

(defun key-type? (value)
  (orelse (erlang:is_atom value)
          (string? value)))

(defun string? (value)
  (andalso (erlang:is_list value)
           (io_lib:printable_list value)))

(defun ensure-string (value)
  (cond ((erlang:is_atom value) (atom_to_list value))
        ((string? value) value)
        (true (lists:flatten (io_lib:format "~p" (list value))))))

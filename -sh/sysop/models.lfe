(defmodule sysop-models
  "Core object and capability representations used by the sysop tooling."
  (export (make-object 3)
          (make-object 4)
          (make-capability 3)
          (make-policy-graph 2)
          (object-id 1)
          (object-type 1)
          (object-attributes 1)
          (capability-subject 1)
          (capability-target 1)
          (capability-verbs 1)
          (object->map 1)
          (capability->map 1)
          (policy-graph->map 1)
          (policy-graph-objects 1)
          (policy-graph-capabilities 1)
          (object-by-type 2)
          (object-by-id 2)))

(defrecord object id type attributes)
(defrecord capability subject target verbs)
(defrecord policy-graph objects capabilities)

(defun make-object (id type)
  (make-object id type '()))

(defun object->map (obj)
  (let ((attrs (lists:map #'attribute->pair/1 (object-attributes obj))))
    (list (tuple "id" (object-id obj))
          (tuple "type" (normalize-type (object-type obj)))
          (tuple "attributes" attrs))))

(defun attribute->pair (attr)
  (case attr
    ((tuple key value)
     (tuple (normalize-key key) value))
    (_ attr)))

(defun normalize-key (key)
  (cond ((erlang:is_atom key) (atom_to_list key))
        ((erlang:is_list key) key)
        (true (io_lib:format "~p" (list key)))))

(defun normalize-type (value)
  (cond ((erlang:is_atom value) (atom_to_list value))
        ((erlang:is_list value) value)
        (true (io_lib:format "~p" (list value)))))

(defun capability->map (cap)
  (list (tuple "from" (capability-subject cap))
        (tuple "to" (capability-target cap))
        (tuple "verbs" (lists:map #'verb->string/1 (capability-verbs cap)))))

(defun verb->string (verb)
  (cond ((erlang:is_atom verb) (atom_to_list verb))
        ((erlang:is_list verb) verb)
        (true (io_lib:format "~p" (list verb)))))

(defun policy-graph->map (graph)
  (list (tuple "objects" (lists:map #'object->map/1 (policy-graph-objects graph)))
        (tuple "capabilities" (lists:map #'capability->map/1 (policy-graph-capabilities graph)))))

(defun object-by-type (type objects)
  (case (lists:keyfind type 1 (lists:map #'object-type-pair/1 objects))
    ((tuple _ obj) obj)
    (_ 'false)))

(defun object-type-pair (obj)
  (tuple (object-type obj) obj))

(defun object-by-id (id objects)
  (case (lists:keyfind id 1 (lists:map #'object-id-pair/1 objects))
    ((tuple _ obj) obj)
    (_ 'false)))

(defun object-id-pair (obj)
  (tuple (object-id obj) obj))

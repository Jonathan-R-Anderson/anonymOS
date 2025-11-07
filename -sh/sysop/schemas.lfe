(defmodule sysop-schemas
  "Validation helpers and strongly-typed records for sysop requests and plans."
  (export (build-create-user-request 2)
          (creation-plan->map 1)
          (build-creation-plan 3)
          (create-user-request-username 1)
          (create-user-request-fs-profile 1)
          (creation-plan-profile 1)
          (creation-plan-policy-graph 1)
          (creation-plan-security-artifacts 1)))

(defrecord create-user-request username fs-profile)
(defrecord creation-plan profile policy-graph security-artifacts)

(defun build-create-user-request (username profile)
  (validate-username username)
  (let ((normalized (validate-profile profile)))
    (make-create-user-request username normalized)))

(defun validate-username (username)
  (cond ((not (erlang:is_list username)) (erlang:error (tuple 'invalid_username username)))
        ((=:= username "") (erlang:error (tuple 'invalid_username username)))
        (true 'ok)))

(defun validate-profile (profile)
  (cond ((not (erlang:is_list profile)) (erlang:error (tuple 'invalid_profile profile)))
        (true (let* ((normalized (string:lowercase profile))
                     (valid? (lists:member normalized (sysop-fs-profiles:supported-profiles))))
                 (case valid?
                   ('true normalized)
                   (_ (erlang:error (tuple 'invalid_profile profile))))))))

(defun build-creation-plan (profile graph artifacts)
  (make-creation-plan profile graph artifacts))

(defun creation-plan->map (plan)
  (let* ((graph (creation-plan-policy-graph plan))
         (graph-map (sysop-models:policy-graph->map graph))
         (objects (lookup "objects" graph-map))
         (capabilities (lookup "capabilities" graph-map)))
    (list (tuple "profile" (creation-plan-profile plan))
          (tuple "objects" objects)
          (tuple "capabilities" capabilities)
          (tuple "policy_graph" graph-map)
          (tuple "security_artifacts" (creation-plan-security-artifacts plan)))))

(defun lookup (key pairs)
  (case (lists:keyfind key 1 pairs)
    ((tuple _ value) value)
    (_ '())))

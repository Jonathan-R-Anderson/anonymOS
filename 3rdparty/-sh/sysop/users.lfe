(defmodule sysop-users
  "High-level orchestration for creating user provisioning plans."
  (export (create_user 1)))

(defun create_user (request)
  (let* ((username (sysop-schemas:create-user-request-username request))
         (profile-id (sysop-schemas:create-user-request-fs-profile request))
         (profile (sysop-fs-profiles:resolve-profile profile-id))
         (graph (build-policy-graph username profile))
         (artifacts (sysop-policy-gen:generate profile graph request))
         (plan (sysop-schemas:build-creation-plan (sysop-fs-profiles:profile-name profile) graph artifacts)))
    plan))

(defun build-policy-graph (username profile)
  (let* ((user-id (object-id "user" username))
         (group-id (object-id "group" username))
         (home-id (object-id "home" username))
         (process-id (object-id "process" username))
         (user (sysop-models:make-object user-id 'user (user-attributes username group-id profile)))
         (group (sysop-models:make-object group-id 'group (group-attributes username user-id)))
         (home (sysop-models:make-object home-id 'home (home-attributes username user-id group-id profile)))
         (process (sysop-models:make-object process-id 'process (process-attributes username user-id group-id profile)))
         (objects (list user group home process))
         (capabilities (build-capabilities user-id group-id home-id process-id)))
    (sysop-models:make-policy-graph objects capabilities)))

(defun object-id (prefix username)
  (lists:flatten (io_lib:format "object:~s:~s" (list prefix username))))

(defun user-attributes (username group-id profile)
  (list (tuple 'username username)
        (tuple 'primary_group group-id)
        (tuple 'fs_profile (sysop-fs-profiles:profile-name profile))))

(defun group-attributes (_username user-id)
  (list (tuple 'members (list user-id))))

(defun home-attributes (username user-id group-id profile)
  (let ((profile-attrs (sysop-fs-profiles:home-attributes profile username)))
    (lists:append profile-attrs (list (tuple 'owner user-id)
                                      (tuple 'group group-id)))))

(defun process-attributes (username user-id group-id profile)
  (let ((profile-attrs (sysop-fs-profiles:process-attributes profile username)))
    (lists:append profile-attrs (list (tuple 'user user-id)
                                      (tuple 'group group-id)))))

(defun build-capabilities (user-id group-id home-id process-id)
  (list (sysop-models:make-capability user-id home-id '(own read write exec))
        (sysop-models:make-capability group-id home-id '(read exec))
        (sysop-models:make-capability user-id process-id '(own exec signal))
        (sysop-models:make-capability process-id home-id '(read write exec))
        (sysop-models:make-capability user-id group-id '(own))))

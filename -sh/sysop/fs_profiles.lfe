(defmodule sysop-fs-profiles
  "Filesystem profile definitions for the sysop tooling."
  (export (supported-profiles 0)
          (normalize-profile 1)
          (resolve-profile 1)
          (profile-name 1)
          (home-attributes 2)
          (process-attributes 2)
          (default-mode 1)
          (policy-generator-key 1)))

(defrecord filesystem-profile name default-mode home-fn process-fn generator-key)

(defun supported-profiles ()
  '("windows" "linux" "unix"))

(defun normalize-profile (profile)
  (string:lowercase profile))

(defun resolve-profile (profile)
  (case (normalize-profile profile)
    ("windows" (windows-profile))
    ("linux" (linux-profile))
    ("unix" (unix-profile))
    (_ (erlang:error (tuple 'invalid_profile profile)))))

(defun profile-name (profile)
  (filesystem-profile-name profile))

(defun home-attributes (profile username)
  ((filesystem-profile-home-fn profile) username))

(defun process-attributes (profile username)
  ((filesystem-profile-process-fn profile) username))

(defun default-mode (profile)
  (filesystem-profile-default-mode profile))

(defun policy-generator-key (profile)
  (filesystem-profile-generator-key profile))

(defun windows-profile ()
  (make-filesystem-profile "windows" "0700" #'windows-home-attributes/1 #'windows-process-attributes/1 'windows))

(defun windows-home-attributes (username)
  (let* ((title (string:titlecase username))
         (path (lists:concat (list "C:\\Users\\" title))))
    (list (tuple 'path path)
          (tuple 'profile "windows")
          (tuple 'filesystem "ntfs")
          (tuple 'mode "0700"))))

(defun windows-process-attributes (_username)
  (list (tuple 'command "powershell.exe")
        (tuple 'arguments '("-NoLogo"))
        (tuple 'profile "windows")
        (tuple 'integrity "Medium")))

(defun linux-profile ()
  (make-filesystem-profile "linux" "0750" #'linux-home-attributes/1 #'linux-process-attributes/1 'linux))

(defun linux-home-attributes (username)
  (let ((path (lists:concat (list "/home/" username))))
    (list (tuple 'path path)
          (tuple 'profile "linux")
          (tuple 'mode "0750")
          (tuple 'selinux_type "user_home_t"))))

(defun linux-process-attributes (_username)
  (list (tuple 'command "/bin/bash")
        (tuple 'arguments '("-l"))
        (tuple 'profile "linux")
        (tuple 'environment (list (tuple "TERM" "xterm-256color")))))

(defun unix-profile ()
  (make-filesystem-profile "unix" "0750" #'unix-home-attributes/1 #'unix-process-attributes/1 'unix))

(defun unix-home-attributes (username)
  (let ((path (lists:concat (list "/home/" username))))
    (list (tuple 'path path)
          (tuple 'profile "unix")
          (tuple 'mode "0750"))))

(defun unix-process-attributes (_username)
  (list (tuple 'command "/bin/sh")
        (tuple 'arguments '("-l"))
        (tuple 'profile "unix")))

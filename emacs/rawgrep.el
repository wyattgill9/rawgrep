;;; rawgrep.el --- Emacs integration for rawgrep -*- lexical-binding: t; -*-

;; Copyright (C) 2025

;; Author: Mark Tyrkba <marktyrkba456@gmail.com>
;; Version: 0.1.0
;; Package-Requires: ((emacs "24.1"))
;; Keywords: tools, grep, search
;; URL: https://github.com/rakivo/rawgrep

;;; Commentary:

;; This package provides Emacs integration for rawgrep, a fast grep alternative.
;; It allows you to interactively search using rawgrep with jumpable results.

;;; Code:

(defgroup rawgrep nil
  "Emacs integration for rawgrep."
  :group 'tools
  :prefix "rawgrep-")

(defcustom rawgrep-executable (executable-find "rawgrep")
  "Path to the rawgrep executable."
  :type 'string
  :group 'rawgrep)

(defun rawgrep ()
  "Perform rawgrep search"
  (interactive)
  (unless rawgrep-executable
    (error "Cannot find rawgrep executable.  Please set `rawgrep-executable'"))
  (let* ((command-template (format "%s  --jump %s"
                                   rawgrep-executable
                                   default-directory))
         (cursor-pos (+ (length rawgrep-executable) 2)))
    (grep-find (read-string "Run rawgrep: "
                            (cons command-template cursor-pos)))))

;;;###autoload
(defun rawgrep-set-keybinding ()
  "Set the default keybinding for rawgrep (M-e)."
  (interactive)
  (global-set-key (kbd "M-e") 'rawgrep))

(provide 'rawgrep)

;;; rawgrep.el ends here

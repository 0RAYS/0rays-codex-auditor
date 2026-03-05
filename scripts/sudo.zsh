# ------------------------------------------------------------------------------
# Description
# -----------
#
# sudo or sudo -e (replacement for sudoedit) will be inserted before the command
#
# ------------------------------------------------------------------------------
# Authors
# -------
#
# * Dongweiming <ciici123@gmail.com>
# * Subhaditya Nath <github.com/subnut>
# * Marc Cornellà <github.com/mcornella>
# * Carlo Sala <carlosalag@protonmail.com>
#
# ------------------------------------------------------------------------------
# Modified By
# -----------
# * RocketDev
# ------------------------------------------------------------------------------
# CREDIT
# This file is from https://github.com/ohmyzsh/ohmyzsh/blob/master/plugins/sudo/sudo.plugin.zsh
# and distribute under the same license, please check that out in the original repo

__sudo-replace-buffer() {
  local old=$1 new=$2 space=${2:+ }

  # if the cursor is positioned in the $old part of the text, make
  # the substitution and leave the cursor after the $new text
  if [[ $CURSOR -le ${#old} ]]; then
    BUFFER="${new}${space}${BUFFER#$old }"
    CURSOR=${#new}
  # otherwise just replace $old with $new in the text before the cursor
  else
    LBUFFER="${new}${space}${LBUFFER#$old }"
  fi
}

sudo-command-line() {
  # If line is empty, quit
  [[ -z $BUFFER ]] && return

  # Save beginning space
  local WHITESPACE=""
  if [[ ${LBUFFER:0:1} = " " ]]; then
    WHITESPACE=" "
    LBUFFER="${LBUFFER:1}"
  fi

  # Just switch sudo
  case "$BUFFER" in
    sudo\ -e\ *) __sudo-replace-buffer "sudo -e" "" ;;
    sudo\ *) __sudo-replace-buffer "sudo" "" ;;
    *) LBUFFER="sudo $LBUFFER" ;;
  esac
  return

  # Preserve beginning space
  LBUFFER="${WHITESPACE}${LBUFFER}"

  # Redisplay edit buffer (compatibility with zsh-syntax-highlighting)
  zle && zle redisplay # only run redisplay if zle is enabled
}

zle -N sudo-command-line

# Defined shortcut keys: [Esc] [Esc]
bindkey -M emacs '\e\e' sudo-command-line
bindkey -M vicmd '\e\e' sudo-command-line
bindkey -M viins '\e\e' sudo-command-line

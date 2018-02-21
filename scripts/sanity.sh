#!/bin/bash

set -eu

# check linux tests

FIRST_OUT="$(git status --porcelain)"
ruby scripts/generate_linux_tests.rb > /dev/null
SECOND_OUT="$(git status --porcelain)"
if [[ "$FIRST_OUT" != "$SECOND_OUT" ]]; then
  printf "\033[0;31mMissing linux test changes!\033[0m\n"
  git --no-pager diff
  exit 1
else
  printf "\033[0;32mLinux tests okay\033[0m\n"
fi

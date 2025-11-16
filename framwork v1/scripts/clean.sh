#!/usr/bin/env bash
set -euo pipefail

# Clean repo artifacts and caches.
# Usage:
#   scripts/clean.sh          # dry-run: show what would be deleted
#   scripts/clean.sh --apply  # actually delete
#   scripts/clean.sh --hard   # delete missions/, artifacts/, logs/, IDE files, caches

apply=0
hard=0
for a in "$@"; do
  case "$a" in
    --apply) apply=1 ;;
    --hard) hard=1 ;;
    *) echo "Unknown arg: $a"; exit 1 ;;
  esac
done

red() { printf '\033[31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

yellow "Clean targets (dry-run=${apply})"

list_matches() {
  case "$1" in
    pycache)   find . -type d -name '__pycache__' ;;
    pyc)       find . -type f -name '*.pyc' ;;
    dsstore)   find . -type f -name '.DS_Store' ;;
    missions)  find missions -mindepth 1 -maxdepth 1 2>/dev/null || true ;;
    artifacts) find artifacts -mindepth 1 -maxdepth 1 2>/dev/null || true ;;
    logs)      find logs -mindepth 1 -maxdepth 1 2>/dev/null || true ;;
    idea)      [[ -d .idea ]] && echo .idea || true ;;
  esac
}

show_bucket() {
  name="$1"; shift
  cnt=$(list_matches "$name" | wc -l | tr -d ' ')
  printf "• %s (%s items)\n" "$name" "$cnt"
}

show_bucket pycache
show_bucket pyc
show_bucket dsstore
if [[ $hard -eq 1 ]]; then
  show_bucket missions
  show_bucket artifacts
  show_bucket logs
  show_bucket idea
fi

if [[ $apply -eq 0 ]]; then
  yellow "Dry-run only. Use --apply to delete."
  exit 0
fi

delete_bucket() {
  name="$1"; shift
  list_matches "$name" | while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    if [[ -d "$p" ]]; then
      rm -rf "$p"
      printf "removed dir: %s\n" "$p"
    elif [[ -f "$p" ]]; then
      rm -f "$p"
      printf "removed file: %s\n" "$p"
    fi
  done
}

delete_bucket pycache
delete_bucket pyc
delete_bucket dsstore
if [[ $hard -eq 1 ]]; then
  delete_bucket missions
  delete_bucket artifacts
  delete_bucket logs
  delete_bucket idea
fi

green "Clean completed."

#!/bin/sh
# Claude Code PostToolUse hook: runs check:spec after an edit to docs/ or the retired-terms list.
# Exit 2 sends the failures back to the agent, which fixes them before going on.
file=$(jq -r '.tool_input.file_path // empty')
case "$file" in
  */docs/*.md|*/scripts/retired-terms.json) ;;
  *) exit 0 ;;
esac
out=$(cd "$CLAUDE_PROJECT_DIR" && node scripts/check-spec.mjs 2>&1) || { echo "$out" >&2; exit 2; }

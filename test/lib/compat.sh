# Sourced by the suites: small shims so they run on Linux, macOS (BSD userland) and
# Windows (Git for Windows' bash).

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) IS_WINDOWS=1 ;;
  *) IS_WINDOWS= ;;
esac

# Octal permission bits of a file: GNU stat, then BSD stat.
file_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

# In-place sed that works with GNU and BSD sed: sedi <sed args...> <file>
sedi() {
  local f="${!#}" tmp
  tmp="$f.sedi.$$"
  sed "${@:1:$#-1}" "$f" >"$tmp" && cat "$tmp" >"$f" && rm -f "$tmp"
}

# Milliseconds since the epoch (BSD date has no %N).
now_ms() {
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    local t="${EPOCHREALTIME/[.,]/}"
    echo $((t / 1000))
  else
    node -e 'console.log(Date.now())'
  fi
}

# Windows has no POSIX permission bits: mode checks are skipped there (and say so).
# check_mode <description> <expected-octal> <path>
check_mode() {
  if [[ -n "$IS_WINDOWS" ]]; then ok "$1 (mode check skipped on Windows)"; return; fi
  local m; m="$(file_mode "$3")"
  [[ "$m" == "$2" ]] && ok "$1" || bad "$1 (mode $m, want $2)"
}

# Run a command with Git Bash's argument path conversion off, for git arguments like
# `origin/j1:.env` that it would otherwise rewrite to `origin\j1;.env`. A no-op elsewhere.
rawargs() { MSYS2_ARG_CONV_EXCL='*' "$@"; }

# A path as native programs (node, git.exe) print it: C:/... on Windows, unchanged elsewhere.
native_path() { if [[ -n "$IS_WINDOWS" ]]; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }

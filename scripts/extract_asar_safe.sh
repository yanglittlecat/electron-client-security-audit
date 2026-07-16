#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: extract_asar_safe.sh <path-to-app.asar> [output-dir] [--force]

Safely extracts an Electron .asar archive without executing application code.
The script only uses a locally available `asar` CLI or `npx --no-install asar`.
It will not install packages or contact the network.

Read boundary:
  The input .asar must resolve to the current working directory or one of its
  subdirectories. This protects against symlink-based reads outside the audit
  scope.

Output boundary:
  The output directory may be outside the current working directory, including
  the parent directory, so auditors can create validation/audit artifacts such
  as ../audit-poc-<product>-<id>. Existing non-empty output directories are
  refused unless --force is supplied.
USAGE
}

FORCE=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) ARGS+=("$arg") ;;
  esac
done

if [[ ${#ARGS[@]} -lt 1 || ${#ARGS[@]} -gt 2 ]]; then
  usage
  exit 2
fi

ASAR_PATH="${ARGS[0]}"
if [[ ! -f "$ASAR_PATH" ]]; then
  echo "[!] Not a file: $ASAR_PATH" >&2
  exit 1
fi

case "$ASAR_PATH" in
  *.asar) ;;
  *) echo "[!] File does not end with .asar: $ASAR_PATH" >&2; exit 1 ;;
esac

if ! command -v realpath >/dev/null 2>&1; then
  echo "[!] realpath is required for safe path resolution." >&2
  exit 1
fi

resolve_output_path() {
  local target="$1"
  local resolved=""

  if resolved="$(realpath -m "$target" 2>/dev/null)"; then
    printf '%s\n' "$resolved"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$target"
  else
    echo "[!] realpath -m is unavailable and python3 was not found for output path resolution." >&2
    return 1
  fi
}

ROOT_REAL="$(pwd -P)"
ASAR_REAL="$(realpath "$ASAR_PATH")"
case "$ASAR_REAL" in
  "$ROOT_REAL"/*|"$ROOT_REAL") ;;
  *) echo "[!] Refusing to read ASAR outside current working directory: $ASAR_REAL" >&2; exit 1 ;;
esac

if [[ ${#ARGS[@]} -eq 2 ]]; then
  OUT_DIR="${ARGS[1]}"
else
  BASE="$(basename "$ASAR_PATH" .asar)"
  OUT_DIR="audit-artifacts/asar-unpacked/${BASE}"
fi

OUT_REAL="$(resolve_output_path "$OUT_DIR")"
if [[ -d "$OUT_REAL" && "$(find "$OUT_REAL" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" != "" && "$FORCE" -ne 1 ]]; then
  echo "[!] Output directory already exists and is not empty: $OUT_REAL" >&2
  echo "[!] Choose a new directory or rerun with --force." >&2
  exit 1
fi

mkdir -p "$OUT_REAL"

case "$OUT_REAL" in
  "$ROOT_REAL"/*|"$ROOT_REAL") ;;
  *) echo "[*] Output directory is outside current working directory by request: $OUT_REAL" ;;
esac

echo "[*] Extracting: $ASAR_REAL"
echo "[*] Output dir: $OUT_REAL"

if command -v asar >/dev/null 2>&1; then
  asar extract "$ASAR_REAL" "$OUT_REAL"
elif command -v npx >/dev/null 2>&1; then
  npx --no-install asar extract "$ASAR_REAL" "$OUT_REAL"
else
  echo "[!] No local asar CLI found and npx is unavailable." >&2
  echo "[!] Install/use asar only in an authorized, isolated environment, then rerun." >&2
  exit 1
fi

echo "[+] Done. No application code was executed."

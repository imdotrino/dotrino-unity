#!/usr/bin/env bash
# Corre las pruebas en el Mono de Unity, que es el runtime que importa: ahí ECDsa y
# ECDiffieHellman lanzan NotImplementedException, así que solo vale lo que pase aquí.
#   UNITY=~/Unity/Hub/Editor/6000.6.5f1 Tests~/mono.sh
set -euo pipefail
cd "$(dirname "$0")/.."
UNITY="${UNITY:-$HOME/Unity/Hub/Editor/6000.6.5f1}"
M="$UNITY/Editor/Data/MonoBleedingEdge"
L="$M/lib/mono/4.5"
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
"$M/bin/mono" "$M/lib/mono/msbuild/Current/bin/Roslyn/csc.exe" -nologo -langversion:9 -out:"$OUT/tests.exe" \
  -r:"$L/Facades/netstandard.dll" -r:"$L/System.Core.dll" -r:"$L/Facades/System.Runtime.dll" \
  -r:"$L/Facades/System.Runtime.InteropServices.RuntimeInformation.dll" -r:"$L/System.dll" \
  $(find Runtime -name '*.cs') 'Tests~/Program.cs'
MONO_PATH="$M/lib/mono/unityjit-linux" "$M/bin/mono" "$OUT/tests.exe" 'Tests~/vectors.json'

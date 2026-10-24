#!/usr/bin/env bash
# El camino directo de verdad: un jugador de Unity para Linux con dos sesiones, cada una con su
# WebRTC, por el proxio de producción. El primer mensaje va por el proxio, el canal se abre por
# debajo y el segundo tiene que llegar por él (Received.Via == "direct").
#   UNITY=~/Unity/Hub/Editor/6000.6.5f1 Tests~/unity-webrtc/run.sh
set -euo pipefail
cd "$(dirname "$0")"
UNITY="${UNITY:-$HOME/Unity/Hub/Editor/6000.6.5f1}"
"$UNITY/Editor/Unity" -batchmode -quit -nographics -projectPath "$PWD" -executeMethod BuildLinux.Run -logFile "$PWD/build.log" >/dev/null 2>&1 \
  || { grep -E "error CS|BUILD" build.log; exit 1; }
./Build/wtest.x86_64 -batchmode -nographics -logFile "$PWD/run.log" >/dev/null 2>&1 || true
grep "DOTRINO-TEST" run.log | sed 's/.*DOTRINO-TEST //'
grep -q "DOTRINO-TEST done 0" run.log

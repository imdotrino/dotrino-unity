#!/usr/bin/env bash
# El backend de Android (Plugins/Android/DotrinoCrypto.java) contra la BCL de .NET, en un JVM
# de escritorio. No prueba el puente JNI de Unity (AndroidCrypto.cs): eso pide un teléfono.
set -euo pipefail
cd "$(dirname "$0")/../.."
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
javac --release 11 -d "$T" Plugins/Android/DotrinoCrypto.java 'Tests~/jvm/JvmCheck.java'
dotnet build 'Tests~/Dotrino.Unity.Tests.csproj' -c Release -v q -nologo >/dev/null
RUN='.artifacts~/bin/Dotrino.Unity.Tests/release/dotrino-unity-tests.dll'
dotnet "$RUN" --jvm-input "$T/state" | java -cp "$T" JvmCheck | dotnet "$RUN" --jvm-check "$T/state"

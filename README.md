# dotrino-unity

El núcleo del ecosistema Dotrino para Unity, en C#: lo que un juego necesita para hablar con
la bóveda sin WebView. Es el puerto de `@dotrino/identity` al mismo nivel que
[`dotrino-native`](https://github.com/imdotrino/dotrino-native) lo es en Swift y Kotlin:
**es un puerto y no decide nada propio**. Si el pilar JS cambia un formato, esto lo sigue, y los
vectores de oro lo hacen saltar.

Hoy (0.3.0) trae:

| Pieza | Puerto de |
|---|---|
| `JsonValue` | un árbol JSON propio (Unity no trae uno fuera del motor) |
| `Canonical` | `canonicalStringify` (`vault/core.js`) |
| `Crypto` | formatos JWK, `verifyDeviceSig`, `wrapForMember`/`openWrap`, `encryptWithCek`/`decryptWithCek`, HKDF |
| `Delegation` | `pubkeyId`, la etiqueta `AB12-CD34`, el papel del aparato (`delegationBody` y su comprobación) |
| `Envelope`, `IdentitySealing` | el sobre de la identidad (v2) y el sellado de `@dotrino/proxy-client` (`{ app, sealed, from }`) |
| `IDeviceKeys`, `SoftwareKeys` | las dos llaves de un aparato (firma y cifrado) |
| `BinPack` | `binpack.js`: el paquete con bytes y la trama binaria del proxio; el sobre sellado binario |
| `ProxyConnection` | el cable de `@dotrino/proxy-client`: `identify` con `aud`, saludo, por token y por llave, canales, llaves de cifrado anunciadas y verificadas, códigos de emparejar |
| `SealedSession` | la sesión que no se cae y lo sella todo (`requireSealed`): reconecta, se re-identifica, re-anuncia su llave, cambia de proxio tras 3 fallos |

## La criptografía es la de cada plataforma

El Mono de Unity declara `ECDsa` y `ECDiffieHellman` pero lanza `NotImplementedException`, y
netstandard2.1 no tiene `AesGcm`. Decidido con el dueño el 2026-10-23: **cripto nativa de cada
plataforma, sin librerías de terceros**. El núcleo pide cuatro primitivas a un `ICryptoBackend`
(firma ECDSA P-256, ECDH P-256, AES-GCM y generar llaves). SHA-256, HMAC y los bytes aleatorios
sí funcionan en Mono y quedan en código gestionado.

| Plataforma | Backend | Probado |
|---|---|---|
| Linux (escritorio) | `OpenSslCrypto`: libcrypto 3 del sistema, API EVP | vectores y proxio vivo, en .NET y en el Mono de Unity |
| Windows | `CngCrypto`: CNG (`bcrypt.dll`) | vectores y proxio vivo en .NET 9 y .NET Framework 4.8 (VM Win11); CI en windows-latest |
| macOS | `AppleCrypto`: CryptoKit por `Plugins/iOS/DotrinoCrypto.swift`, compilado a `Plugins/macOS/libDotrinoCrypto.dylib` (universal) | vectores y proxio vivo en .NET 9 (Mac Intel); CI en macos-14 (Apple Silicon) |
| iOS | `AppleCrypto`, la misma fuente Swift: Unity la mete en el proyecto de Xcode | **sin probar**: falta un build de iOS |
| Android | `AndroidCrypto`: `javax.crypto` por JNI (`Plugins/Android/DotrinoCrypto.java`, ensamblado aparte porque necesita `UnityEngine`) | la clase Java contra la BCL en un JVM (`Tests~/jvm/check.sh`, CI). **El puente JNI sin probar**: Unity 6.6 ya no compila x86_64 para Android y el emulador cae en el driver gráfico antes de llegar al código; hace falta un teléfono |
| .NET 8+ (un servidor, las pruebas) | `BclCrypto` | referencia de todas las pruebas cruzadas |

El backend se elige solo según la plataforma. Una plataforma sin backend lanza
`PlatformNotSupportedException` con su nombre: no hay repliegue a algo que solo parezca firmar.

**Dónde viven las llaves** (CONVENCIONES §16.2): en Android e iOS, donde las guarda
`dotrino-native` (el juego no tiene llave propia); en escritorio, el juego es un aparato del acta,
enrolado con la bóveda, con la llave sellada en el disco. `IDeviceKeys` es esa frontera: en un
teléfono la implementa el puente a `dotrino-native`, en escritorio `SoftwareKeys`.

## El transporte

`SealedSession` es lo que usa un juego: todo sale sellado y en binario, y lo que llega sin sellar
se descarta y se avisa (`Warn`), en las dos direcciones. Los eventos se lanzan en el
`SynchronizationContext` en el que se creó la sesión: en Unity, el hilo principal.

```csharp
var session = new SealedSession(new[] { "wss://proxy.dotrino.com" }, keys, "autoball");
session.Message += m => Debug.Log(m.Payload["op"].Str + " de " + m.FromPubkey);
session.Start();
await session.AwaitOnline();
await session.SendSealed(otherPubkey, new JsonObject { { "op", "kickoff" } });
```

**Solo el último escalón todavía.** Todo va por el proxio. El camino directo (WebRTC directo,
Bluetooth, TURN) no está, así que esto todavía no cumple la regla de preferir el camino más
directo (CLAUDE.md, 2026-09-03). Es lo siguiente del transporte.

## Usarlo en un proyecto de Unity

`Packages/manifest.json`:

```json
"com.dotrino.unity": "https://github.com/imdotrino/dotrino-unity.git#v0.3.0"
```

```csharp
using Dotrino;

using var keys = SoftwareKeys.Generate();
var data = new JsonObject { { "op", "identify" }, { "ts", 1 } };
string sig = await keys.Sign(Canonical.Stringify(data));
bool ok = Crypto.Verify(keys.Publickey, data, sig);
```

## Pruebas

Los vectores (`Tests~/vectors.json`) son **el mismo archivo** que prueba `dotrino-native`, sacado
del pilar con su `test-vectors/gen.mjs`; CI comprueba que no se desincronizó.

```bash
dotnet build 'Tests~/Dotrino.Unity.Tests.csproj' -c Release
dotnet '.artifacts~/bin/Dotrino.Unity.Tests/release/dotrino-unity-tests.dll'   # BCL + OpenSSL, .NET 9
'Tests~/mono.sh'                                                               # el Mono de Unity
DOTRINO_LIVE_PROXY=wss://proxy.dotrino.com 'Tests~/mono.sh'                     # y contra el proxio de verdad
```

Con `DOTRINO_LIVE_PROXY` se suma la prueba viva: dos sesiones con identidades de usar y tirar se
hablan selladas por llave (cola del proxio) y por token (saludo y en vivo). CI no la corre: toca
producción.

La de `mono.sh` es la que cuenta: compila con el Roslyn que trae Unity y corre en su Mono. CI todavía
no la corre (necesita Unity instalado).

Las carpetas con `~` (`Tests~`, `.artifacts~`, `Native~`) Unity no las importa.

La dylib de macOS se compila con `Native~/build-mac.sh` en un Mac con Xcode y se sube al repo
(un paquete de Unity por git no puede compilarla). CI la vuelve a compilar desde la fuente y
prueba esa.

## Lo que falta

- Probar iOS y el puente JNI de Android en aparatos de verdad (tabla de arriba).
- Las llaves de la persona en el teléfono: `IDeviceKeys` sobre `dotrino-native` (Identidad Dotrino
  en Android, los grupos del equipo en iOS). Hoy los backends móviles solo hacen la cripto, no
  guardan la llave de nadie.
- El camino directo del transporte (WebRTC, Bluetooth, TURN) y listar canales.
- Enrolar el aparato de escritorio con la bóveda y guardar su llave sellada.
- El acta (`memberCan`, `verifyActa`), el almacén (`@dotrino/store`) y `@dotrino/compat`.

## Licencia

MIT

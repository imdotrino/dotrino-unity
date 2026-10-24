# dotrino-unity

El núcleo del ecosistema Dotrino para Unity, en C#: lo que un juego necesita para hablar con
la bóveda sin WebView. Es el puerto de `@dotrino/identity` al mismo nivel que
[`dotrino-native`](https://github.com/imdotrino/dotrino-native) lo es en Swift y Kotlin:
**es un puerto y no decide nada propio**. Si el pilar JS cambia un formato, esto lo sigue, y los
vectores de oro lo hacen saltar.

Hoy (0.1.0) trae:

| Pieza | Puerto de |
|---|---|
| `JsonValue` | un árbol JSON propio (Unity no trae uno fuera del motor) |
| `Canonical` | `canonicalStringify` (`vault/core.js`) |
| `Crypto` | formatos JWK, `verifyDeviceSig`, `wrapForMember`/`openWrap`, `encryptWithCek`/`decryptWithCek`, HKDF |
| `Delegation` | `pubkeyId`, la etiqueta `AB12-CD34`, el papel del aparato (`delegationBody` y su comprobación) |
| `Envelope`, `IdentitySealing` | el sobre de la identidad (v2) y el sellado de `@dotrino/proxy-client` (`{ app, sealed, from }`) |
| `IDeviceKeys`, `SoftwareKeys` | las dos llaves de un aparato (firma y cifrado) |

## La criptografía es la de cada plataforma

El Mono de Unity declara `ECDsa` y `ECDiffieHellman` pero lanza `NotImplementedException`, y
netstandard2.1 no tiene `AesGcm`. Decidido con el dueño el 2026-10-23: **cripto nativa de cada
plataforma, sin librerías de terceros**. El núcleo pide cuatro primitivas a un `ICryptoBackend`
(firma ECDSA P-256, ECDH P-256, AES-GCM y generar llaves). SHA-256, HMAC y los bytes aleatorios
sí funcionan en Mono y quedan en código gestionado.

| Plataforma | Backend | Estado |
|---|---|---|
| Linux (escritorio) | `OpenSslCrypto`: libcrypto 3 del sistema, API EVP | hecho |
| .NET 8+ (un servidor, las pruebas) | `BclCrypto` | hecho |
| Windows | CNG (`bcrypt.dll`) | falta |
| macOS | Security.framework / CryptoKit por `dotrino-native` | falta |
| Android | `dotrino-native` (Kotlin) por JNI; las llaves en Identidad Dotrino (§16) | falta |
| iOS | `dotrino-native` (Swift); las llaves en los grupos del equipo (§16) | falta |

El backend se elige solo según la plataforma. Una plataforma sin backend lanza
`PlatformNotSupportedException` con su nombre: no hay repliegue a algo que solo parezca firmar.

**Dónde viven las llaves** (CONVENCIONES §16.2): en Android e iOS, donde las guarda
`dotrino-native` (el juego no tiene llave propia); en escritorio, el juego es un aparato del acta,
enrolado con la bóveda, con la llave sellada en el disco. `IDeviceKeys` es esa frontera: en un
teléfono la implementa el puente a `dotrino-native`, en escritorio `SoftwareKeys`.

## Usarlo en un proyecto de Unity

`Packages/manifest.json`:

```json
"com.dotrino.unity": "https://github.com/imdotrino/dotrino-unity.git#v0.1.0"
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
```

La segunda es la que cuenta: compila con el Roslyn que trae Unity y corre en su Mono. CI todavía
no la corre (necesita Unity instalado).

Las carpetas con `~` (`Tests~`, `.artifacts~`) Unity no las importa.

## Lo que falta

- Backends de Windows, macOS, Android e iOS (tabla de arriba).
- El transporte: el cable de `@dotrino/proxy-client` (`identify`, `sendSealed`, canales) sobre
  WebSocket, con los escalones del §transporte.
- Enrolar el aparato de escritorio con la bóveda y guardar su llave sellada.
- El acta (`memberCan`, `verifyActa`), el almacén (`@dotrino/store`) y `@dotrino/compat`.

## Licencia

MIT

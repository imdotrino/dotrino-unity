# El lanzador de juegos de escritorio — diseño

> Conversado con el dueño el 2026-10-23. **Borrador**: lo que está decidido va marcado así; el
> resto son preguntas abiertas, y no se programa nada hasta cerrarlas.

## Qué es

Una app de escritorio (Windows, macOS, Linux) con dos trabajos:

1. **El catálogo**: enseña los juegos de Dotrino, los instala, los actualiza con la firma
   verificada (como ya se actualiza la bóveda, sigstore), los abre y los desinstala. *(Decidido:
   un lanzador que instala, no una lista de enlaces.)*
2. **La identidad del PC para los juegos**: tiene las llaves de la cuenta en este aparato, y los
   juegos le piden firmar o abrir sobres por un **socket local** (el escalón 1 del transporte).
   Un juego nunca tiene llaves propias.

Es el equivalente de **Identidad Dotrino** en Android (CONVENCIONES §16.2): una pieza que guarda
la identidad para todas las apps del aparato, porque una app sola no puede compartir su llave con
las otras.

## La identidad y la bóveda son piezas distintas *(decidido)*

El lanzador **no es una bóveda**. Es **un aparato más del acta**, como el teléfono:

- tiene su llave de aparato, y lo que puede hacer (`sign`, …) lo dice el acta;
- **se empareja con la bóveda esté donde esté** (otro PC, el VPS, la alojada), con invitación y
  código, como cualquier aparato;
- **sin un camino especial para la misma máquina** *(decidido)*: aunque la bóveda corra en el
  mismo PC, el emparejamiento es el normal. Se valoró reconocerse solos por el socket local y se
  descartó: abriría un agujero, y la regla «sin invitación no se enrola» no tiene excepciones.

No hace falta multivault para esto: multivault es tener otra bóveda, y el lanzador no lo es.

Por qué no meter la identidad de los juegos dentro de la bóveda: **ninguna app puede exigir que
el usuario tenga un daemon encendido** (CLAUDE.md, «el aparato cumple el rol»). Si los juegos
dependieran de la bóveda, la bóveda pasaría a ser obligatoria para jugar.

## Cómo habla un juego con el lanzador

```
juego (Unity, dotrino-unity)  ──socket local──▶  lanzador  ──acta──▶  llaves de la cuenta
      IDeviceKeys remoto                              firma / ECDH, según el acta
```

- En `dotrino-unity`, el lanzador es **otra implementación de `IDeviceKeys`** (como lo será
  `dotrino-native` en el teléfono). El juego pide `Sign` y `Agree`; las llaves no salen del lanzador.
- El socket local: Unix socket en Linux y macOS, named pipe en Windows; solo el usuario de la
  sesión puede abrirlo.
- El lanzador sabe **qué juego** le habla (lo lanzó él, o lo verifica por la ruta instalada), y
  eso va en lo que firma, como el `onBehalfOf` del iframe de la identidad: el usuario ve qué juego
  firmó qué.

## Preguntas abiertas (las decide el dueño)

1. **¿Qué pasa sin bóveda?** ¿El lanzador puede ser la cuenta él solo («este aparato es bóveda»,
   como `startDeviceVault` en el navegador), o exige emparejar con una? Lo primero cumple «el
   aparato cumple el rol»; lo segundo es más simple.
2. **¿Con qué se hace la ventana?** La bóveda ya tiene una en Rust + iced con instaladores
   para los tres sistemas que se actualizan solos (`dotrino-vault/desktop`). Reusar ese
   esqueleto es lo barato.
3. **El nombre** y su repo (`dotrino-games`, `dotrino-launcher`…).
4. **¿Cuesta?** Las apps nativas de tienda se pagan; esto se distribuiría fuera de tiendas.
5. **¿Qué ve un jugador de otro?** El perfil (`<dotrino-profile>`) y la reputación ya existen
   en el ecosistema; el lanzador podría enseñarlos sin que cada juego lo reimplemente.

## Fuera de este documento

El matchmaking y el servidor de cada juego (autoball tiene el suyo en AWS) no son del lanzador.

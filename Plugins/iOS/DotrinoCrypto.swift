// Apple (macOS and iOS): the crypto primitives of dotrino-unity, from CryptoKit — the only
// public AES-GCM on Apple platforms is Swift, so this small file exports C functions that the
// C# side calls (`AppleCrypto.cs`). On iOS Unity compiles it into the Xcode project; for macOS
// it is built into Plugins/macOS/libDotrinoCrypto.dylib by Native~/build-mac.sh.
//
// Raw big-endian bytes in and out: d, x, y (32 each), P1363 signatures (64), AES-GCM ct‖tag.
// Every function returns 0 on success and a negative code otherwise.

import CryptoKit
import Foundation

private func bytes(_ p: UnsafePointer<UInt8>, _ n: Int32) -> Data { Data(bytes: p, count: Int(n)) }
private func put(_ d: Data, _ out: UnsafeMutablePointer<UInt8>) { d.copyBytes(to: out, count: d.count) }

@_cdecl("dotrino_p256_generate")
public func dotrino_p256_generate(_ d: UnsafeMutablePointer<UInt8>, _ x: UnsafeMutablePointer<UInt8>, _ y: UnsafeMutablePointer<UInt8>) -> Int32 {
    let k = P256.Signing.PrivateKey()
    let pub = k.publicKey.rawRepresentation   // x‖y
    put(k.rawRepresentation, d)
    put(pub.prefix(32), x)
    put(pub.suffix(32), y)
    return 0
}

@_cdecl("dotrino_p256_sign")
public func dotrino_p256_sign(_ d: UnsafePointer<UInt8>, _ msg: UnsafePointer<UInt8>, _ len: Int32, _ sig: UnsafeMutablePointer<UInt8>) -> Int32 {
    guard let k = try? P256.Signing.PrivateKey(rawRepresentation: bytes(d, 32)),
          let s = try? k.signature(for: bytes(msg, len)) else { return -1 }
    put(s.rawRepresentation, sig)
    return 0
}

/// 0: valid. 1: not valid. Negative: the key could not be read.
@_cdecl("dotrino_p256_verify")
public func dotrino_p256_verify(_ x: UnsafePointer<UInt8>, _ y: UnsafePointer<UInt8>, _ msg: UnsafePointer<UInt8>, _ len: Int32, _ sig: UnsafePointer<UInt8>) -> Int32 {
    guard let k = try? P256.Signing.PublicKey(rawRepresentation: bytes(x, 32) + bytes(y, 32)) else { return -1 }
    guard let s = try? P256.Signing.ECDSASignature(rawRepresentation: bytes(sig, 64)) else { return 1 }
    return k.isValidSignature(s, for: bytes(msg, len)) ? 0 : 1
}

@_cdecl("dotrino_p256_ecdh")
public func dotrino_p256_ecdh(_ d: UnsafePointer<UInt8>, _ px: UnsafePointer<UInt8>, _ py: UnsafePointer<UInt8>, _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    guard let k = try? P256.KeyAgreement.PrivateKey(rawRepresentation: bytes(d, 32)),
          let p = try? P256.KeyAgreement.PublicKey(rawRepresentation: bytes(px, 32) + bytes(py, 32)),
          let s = try? k.sharedSecretFromKeyAgreement(with: p) else { return -1 }
    s.withUnsafeBytes { raw in out.update(from: raw.bindMemory(to: UInt8.self).baseAddress!, count: 32) }
    return 0
}

/// `out` gets plain.count + 16 bytes: the ciphertext and then the tag.
@_cdecl("dotrino_aesgcm_seal")
public func dotrino_aesgcm_seal(_ key: UnsafePointer<UInt8>, _ keyLen: Int32, _ iv: UnsafePointer<UInt8>, _ ivLen: Int32,
                                _ plain: UnsafePointer<UInt8>, _ len: Int32, _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    guard let nonce = try? AES.GCM.Nonce(data: bytes(iv, ivLen)),
          let box = try? AES.GCM.seal(bytes(plain, len), using: SymmetricKey(data: bytes(key, keyLen)), nonce: nonce) else { return -1 }
    put(box.ciphertext + box.tag, out)
    return 0
}

/// -2: the tag does not match (tampered, or the wrong key).
@_cdecl("dotrino_aesgcm_open")
public func dotrino_aesgcm_open(_ key: UnsafePointer<UInt8>, _ keyLen: Int32, _ iv: UnsafePointer<UInt8>, _ ivLen: Int32,
                                _ sealed: UnsafePointer<UInt8>, _ len: Int32, _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    guard len >= 16, let nonce = try? AES.GCM.Nonce(data: bytes(iv, ivLen)) else { return -1 }
    let all = bytes(sealed, len)
    guard let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: all.prefix(Int(len) - 16), tag: all.suffix(16)) else { return -1 }
    guard let plain = try? AES.GCM.open(box, using: SymmetricKey(data: bytes(key, keyLen))) else { return -2 }
    put(plain, out)
    return 0
}

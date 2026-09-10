//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOConcurrencyHelpers
import NIOCore

/// The server's reply to a key exchange, in terms an application-supplied key
/// exchange algorithm can produce and consume.
///
/// NIOSSH's own algorithms work with `SSHMessage.KeyExchangeECDH*`, which are
/// internal to this module. This is the same information in public types, so an
/// algorithm living outside NIOSSH can implement
/// ``NIOSSHKeyExchangeAlgorithmProtocol`` without reaching inside it.
public struct NIOSSHKeyExchangeServerReply {
    public var hostKey: NIOSSHPublicKey
    public var publicKey: ByteBuffer
    public var signature: NIOSSHSignature

    public init(hostKey: NIOSSHPublicKey, publicKey: ByteBuffer, signature: NIOSSHSignature) {
        self.hostKey = hostKey
        self.publicKey = publicKey
        self.signature = signature
    }
}

/// A key exchange algorithm NIOSSH can negotiate and drive.
///
/// This is the public counterpart of the internal `EllipticCurveKeyExchangeProtocol`:
/// same responsibilities, expressed in types available outside the module, plus
/// the two message IDs — an algorithm that is not ECDH (Diffie-Hellman group
/// exchange, say) does not use ECDH's 30/31.
public protocol NIOSSHKeyExchangeAlgorithmProtocol {
    /// The message ID carrying this algorithm's client-to-server init message.
    static var keyExchangeInitMessageId: UInt8 { get }

    /// The message ID carrying this algorithm's server-to-client reply.
    static var keyExchangeReplyMessageId: UInt8 { get }

    /// The names this algorithm is negotiated under, most preferred first.
    static var keyExchangeAlgorithmNames: [Substring] { get }

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?)

    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> ByteBuffer

    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: ByteBuffer,
        serverHostKey: NIOSSHPrivateKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, NIOSSHKeyExchangeServerReply)

    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage: NIOSSHKeyExchangeServerReply,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult
}

/// Registers algorithms NIOSSH does not bundle.
///
/// NIOSSH ships Ed25519 and the NIST curves; anything else — RSA, Diffie-Hellman
/// group exchange, a cipher suite a particular server insists on — is supplied
/// by the application and registered here before a connection is made.
///
/// Registration is process-wide and additive: an algorithm registered twice is
/// stored once. Register before connecting, not while connections are running.
public enum NIOSSHAlgorithms {
    /// Adds a key exchange algorithm to those NIOSSH will offer and accept.
    public static func register(keyExchangeAlgorithm type: NIOSSHKeyExchangeAlgorithmProtocol.Type) {
        _CustomAlgorithms.lock.withLockVoid {
            if !_CustomAlgorithms.keyExchangeAlgorithms.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(type) }) {
                _CustomAlgorithms.keyExchangeAlgorithms.append(type)
            }
        }
    }

    /// Adds a transport protection scheme — a cipher/MAC pairing — to those
    /// NIOSSH will offer and accept.
    public static func register(transportProtectionScheme type: NIOSSHTransportProtection.Type) {
        _CustomAlgorithms.lock.withLockVoid {
            if !_CustomAlgorithms.transportProtectionSchemes.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(type) }) {
                _CustomAlgorithms.transportProtectionSchemes.append(type)
            }
        }
    }

    /// Adds a public key type and its matching signature type, for host keys
    /// and for public key authentication.
    ///
    /// The two are registered together because a key is useless without the
    /// signature type that reads what it produces.
    public static func register<
        PublicKey: NIOSSHPublicKeyProtocol,
        Signature: NIOSSHSignatureProtocol
    >(
        publicKey type: PublicKey.Type,
        signature: Signature.Type
    ) {
        _CustomAlgorithms.lock.withLockVoid {
            if !_CustomAlgorithms.publicKeyAlgorithms.contains(where: { ObjectIdentifier($0) == ObjectIdentifier(type) }) {
                _CustomAlgorithms.publicKeyAlgorithms.append(type)
                _CustomAlgorithms.signatures.append(signature)
            }
        }
    }

    /// Drops every registration. Tests only — registrations are global, so a
    /// test that registers an algorithm would otherwise leak it into the next.
    internal static func unregisterAlgorithms() {
        _CustomAlgorithms.lock.withLockVoid {
            _CustomAlgorithms.transportProtectionSchemes = []
            _CustomAlgorithms.publicKeyAlgorithms = []
            _CustomAlgorithms.signatures = []
            _CustomAlgorithms.keyExchangeAlgorithms = []
        }
    }
}

internal var customTransportProtectionSchemes: [NIOSSHTransportProtection.Type] {
    _CustomAlgorithms.lock.withLock { _CustomAlgorithms.transportProtectionSchemes }
}

internal var customKeyExchangeAlgorithms: [NIOSSHKeyExchangeAlgorithmProtocol.Type] {
    _CustomAlgorithms.lock.withLock { _CustomAlgorithms.keyExchangeAlgorithms }
}

internal var customPublicKeyAlgorithms: [NIOSSHPublicKeyProtocol.Type] {
    _CustomAlgorithms.lock.withLock { _CustomAlgorithms.publicKeyAlgorithms }
}

internal var customSignatures: [NIOSSHSignatureProtocol.Type] {
    _CustomAlgorithms.lock.withLock { _CustomAlgorithms.signatures }
}

/// One lock over all four lists rather than the fork's four. They are only
/// written at start-up and read on every handshake, so contention is not the
/// concern; four locks that must never be taken together is.
private enum _CustomAlgorithms {
    static let lock = NIOLock()
    nonisolated(unsafe) static var transportProtectionSchemes = [NIOSSHTransportProtection.Type]()
    nonisolated(unsafe) static var keyExchangeAlgorithms = [NIOSSHKeyExchangeAlgorithmProtocol.Type]()
    nonisolated(unsafe) static var publicKeyAlgorithms = [NIOSSHPublicKeyProtocol.Type]()
    nonisolated(unsafe) static var signatures = [NIOSSHSignatureProtocol.Type]()
}

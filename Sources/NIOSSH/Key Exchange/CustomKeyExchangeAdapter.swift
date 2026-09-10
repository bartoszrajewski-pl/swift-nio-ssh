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

import NIOCore

/// Presents an application-supplied key exchange algorithm to the key exchange
/// state machine as though it were one of NIOSSH's own.
///
/// The two protocols carry the same information and differ only in how they say
/// it: `EllipticCurveKeyExchangeProtocol` speaks in `SSHMessage.KeyExchangeECDH*`,
/// which is internal to this module, while ``NIOSSHKeyExchangeAlgorithmProtocol``
/// speaks in `ByteBuffer` and ``NIOSSHKeyExchangeServerReply`` so that an
/// algorithm outside the module can implement it at all. The fields line up one
/// for one, so this adapter is pure translation — it makes no protocol
/// decisions of its own.
///
/// Adapting rather than replacing the internal protocol keeps NIOSSH's own key
/// exchange code untouched, which is what makes the next rebase onto upstream
/// cheap.
struct CustomKeyExchangeAdapter<Algorithm: NIOSSHKeyExchangeAlgorithmProtocol>: EllipticCurveKeyExchangeProtocol {
    private var algorithm: Algorithm

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.algorithm = Algorithm(ourRole: ourRole, previousSessionIdentifier: previousSessionIdentifier)
    }

    static var keyExchangeAlgorithmNames: [Substring] {
        Algorithm.keyExchangeAlgorithmNames
    }

    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> SSHMessage.KeyExchangeECDHInitMessage {
        SSHMessage.KeyExchangeECDHInitMessage(
            publicKey: self.algorithm.initiateKeyExchangeClientSide(allocator: allocator)
        )
    }

    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: SSHMessage.KeyExchangeECDHInitMessage,
        serverHostKey: NIOSSHPrivateKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, SSHMessage.KeyExchangeECDHReplyMessage) {
        let (result, reply) = try self.algorithm.completeKeyExchangeServerSide(
            clientKeyExchangeMessage: message.publicKey,
            serverHostKey: serverHostKey,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )
        return (
            result,
            SSHMessage.KeyExchangeECDHReplyMessage(
                hostKey: reply.hostKey,
                publicKey: reply.publicKey,
                signature: reply.signature
            )
        )
    }

    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage message: SSHMessage.KeyExchangeECDHReplyMessage,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult {
        try self.algorithm.receiveServerKeyExchangePayload(
            serverKeyExchangeMessage: NIOSSHKeyExchangeServerReply(
                hostKey: message.hostKey,
                publicKey: message.publicKey,
                signature: message.signature
            ),
            initialExchangeBytes: &initialExchangeBytes,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )
    }
}

extension NIOSSHKeyExchangeAlgorithmProtocol {
    /// Wraps this algorithm in its adapter.
    ///
    /// Called on an existential metatype (`NIOSSHKeyExchangeAlgorithmProtocol.Type`),
    /// which is how the concrete type gets bound to the adapter's generic
    /// parameter — the registry can only store the existential.
    static func makeKeyExchanger(
        ourRole: SSHConnectionRole,
        previousSessionIdentifier: ByteBuffer?
    ) -> EllipticCurveKeyExchangeProtocol {
        CustomKeyExchangeAdapter<Self>(
            ourRole: ourRole,
            previousSessionIdentifier: previousSessionIdentifier
        )
    }
}

# Secure Electronic Contract Signing (SECS)

## 1. Security goals

The SECS system must provide four main security goals:

1. Non-repudiation of origin: Alice cannot credibly deny signing the contract.
2. Non-repudiation of receipt: Bob cannot credibly deny receiving the final signed contract, and Alice cannot deny receiving Bob's signed receipt.
3. Integrity: modifications to the contract must be detected.
4. Confidentiality: the contract terms must not be readable by a network attacker while they are transmitted.

The design assumes Alice and Bob are communicating over a network that may be controlled or observed by an attacker.

---

## 2. Cryptographic primitives

### Digital signatures

Alice and Bob each have a public/private signing key pair and a certificate issued by a trusted Certificate Authority (CA).

Alice uses her private signing key to sign the contract hash and relevant protocol information. Bob uses Alice's public key from her certificate to verify the signature.

Bob also signs a receipt using his private key. This provides evidence that Bob received the signed contract.

Digital signatures are used for non-repudiation and authentication because only the holder of the corresponding private key should be able to create a valid signature.

### Hashing

A cryptographic hash such as SHA-256 is used to calculate a digest of the contract:

`contract_hash = SHA-256(contract)`

The hash is included in the signatures instead of signing the entire contract directly. If any part of the contract changes, its hash will change and the signature verification will fail.

The contract hash is also included in the receipt so that the receipt is tied to exactly the same contract that Bob received.

### Authenticated key exchange

Alice and Bob establish a shared session key using an authenticated Diffie-Hellman key exchange.

Their public keys are authenticated using their CA-issued certificates. The resulting shared secret is used to derive a symmetric encryption key.

This provides confidentiality without requiring Alice and Bob to exchange a symmetric key directly over the network.

### Authenticated encryption

The contract is encrypted using an authenticated encryption scheme such as AES-GCM.

AES-GCM provides confidentiality and integrity for the encrypted contract, provided that a nonce is never reused with the same key.

The nonce is transmitted together with the ciphertext because the nonce does not need to be secret.

### PKI

A trusted Certificate Authority binds each participant's identity to their public key.

Alice and Bob verify the certificates before using the corresponding public keys. Certificate validation includes checking that the certificate is trusted, valid, and associated with the expected identity.

---

## 3. Message flow

The following protocol assumes an attacker can observe, modify, replay, or inject network messages.

```text
                         UNTRUSTED NETWORK
        =====================================================

 Alice                                                     Bob
   |                                                         |
   |  1. Certificate_A + DH_public_A + contract metadata    |
   |-------------------------------------------------------->|
   |                                                         |
   |                         2. Certificate_B + DH_public_B |
   |<--------------------------------------------------------|
   |                                                         |
   |  Both sides validate the other's certificate            |
   |  and derive the shared session key.                      |
   |                                                         |
   |  3. Encrypted contract + nonce +                       |
   |     Alice signature over contract hash + metadata       |
   |-------------------------------------------------------->|
   |                                                         |
   |                         Bob decrypts and verifies:       |
   |                         - AES-GCM authentication         |
   |                         - Alice's certificate            |
   |                         - Alice's signature              |
   |                         - contract hash                  |
   |                                                         |
   |                         4. Signed receipt                |
   |                         containing contract hash,        |
   |                         contract ID and Bob's signature  |
   |<--------------------------------------------------------|
   |                                                         |
   |  Alice verifies Bob's certificate and receipt signature. |
   |                                                         |
   |  5. Signed acknowledgement of receipt                   |
   |-------------------------------------------------------->|
   |                                                         |
        =====================================================
                         TRUST BOUNDARY
```

The main trust boundary is the network between Alice and Bob. The network is not trusted.

The CA is outside the communication channel and is a trusted third party responsible for binding identities to public keys.

ImagenDeber1 is an anex usefull for understanding the flow.
---

## 4. Detailed protocol

### Step 1 — Establish identities

Alice sends her certificate and ephemeral Diffie-Hellman public value to Bob.

Bob sends his certificate and ephemeral Diffie-Hellman public value to Alice.

Both parties validate the other's certificate using the trusted CA.

Neither party should accept a key merely because it was received over the network.

---

### Step 2 — Establish the session key

Alice and Bob perform an authenticated Diffie-Hellman exchange.

Both derive the same shared secret and use a key derivation function to derive the AES-GCM session key.

The ephemeral public keys and the identities of both parties are bound to the protocol transcript so that an attacker cannot substitute keys without detection.

---

### Step 3 — Alice signs and encrypts the contract

Alice calculates:

`H = SHA-256(contract)`

She creates a signature over information such as:

`contract_id || H || Alice_ID || Bob_ID`

Alice then encrypts the contract using AES-GCM with the derived session key and a fresh nonce.

The message sent to Bob contains:

* contract ID
* encrypted contract
* AES-GCM nonce
* Alice's certificate
* Alice's digital signature
* the necessary protocol metadata

The signature allows Bob to verify that the contract originated from Alice and has not been changed.

The AES-GCM encryption prevents a network attacker from reading the contract terms.

---

### Step 4 — Bob verifies and signs a receipt

Bob first authenticates Alice's certificate and verifies Alice's signature.

He decrypts the contract and calculates its SHA-256 hash.

Bob accepts the contract only if the calculated hash matches the hash covered by Alice's signature and the AES-GCM authentication succeeds.

Bob then creates a receipt containing at least:

`contract_id || H || Alice_signature`

Bob signs this receipt using his private signing key.

The receipt is sent back to Alice.

This provides evidence that Bob received the specific contract identified by the hash.

---

### Step 5 — Alice acknowledges the receipt

Alice verifies Bob's certificate and Bob's signature on the receipt.

Alice stores the receipt as evidence that Bob acknowledged receiving the contract.

Alice then sends a signed acknowledgement confirming that she received Bob's receipt.

Both parties therefore have signed evidence associated with the same contract hash.

---

# 5. Control Scorecard — Axis 2 guarantees

## Non-repudiation of origin

**Guarantee:** Alice cannot credibly deny signing the contract because the contract hash and contract metadata are covered by Alice's digital signature.

**Condition:** This guarantee holds provided Alice's private signing key has not been compromised, the signature algorithm remains secure, and the CA has correctly authenticated Alice's identity and has not mis-issued her certificate.

---

## Non-repudiation of receipt

**Guarantee:** Bob cannot credibly deny receiving the final signed contract because he produces a signed receipt containing the contract identifier and cryptographic hash of the contract. Alice also cannot deny receiving Bob's receipt because she sends a signed acknowledgement.

**Condition:** This guarantee holds provided Bob's private signing key has not been compromised, the certificates are correctly validated, the signed receipt is securely preserved, and the contract hash uniquely identifies the received contract.

---

## Integrity

**Guarantee:** Any modification to the contract after signing will be detected because the contract hash covered by Alice's signature will no longer match the modified contract. AES-GCM also detects modifications to the encrypted message.

**Condition:** This guarantee holds provided SHA-256 and the digital signature and AEAD primitives remain cryptographically secure, and AES-GCM never reuses a nonce with the same key.

---

## Confidentiality

**Guarantee:** A network attacker observing the communication cannot recover the contract terms from the transmitted ciphertext.

**Condition:** This guarantee holds provided the Diffie-Hellman exchange is authenticated, the session key remains secret, the encryption primitive remains secure, and the session key and private keys have not been compromised.

---

# 6. Which mistakes from the six broken deployments does SECS avoid?

The SECS design avoids the mistakes found in the broken deployments as follows.

### 1. Reused one-time pad

The broken deployment reused the same pad for multiple messages, allowing relationships between plaintexts to be recovered.

SECS does not use a reused one-time pad. It establishes a fresh session key and uses authenticated encryption with a fresh nonce for each encryption.

---

### 2. ECB structure leakage

The ECB deployment encrypted identical plaintext blocks independently, allowing repeated ciphertext blocks to reveal relationships between records.

SECS does not use ECB. The contract is encrypted using an authenticated encryption mode such as AES-GCM with a unique nonce, so plaintext structure is not directly exposed through repeated independent blocks.

---

### 3. CTR nonce reuse

The CTR deployment reused a nonce with the same key, causing the keystream to be reused and allowing attackers to calculate relationships between plaintexts.

SECS uses AES-GCM with a fresh nonce for each encryption under a given key. The protocol therefore avoids the nonce-reuse condition that caused the CTR failure.

---

### 4. Length extension in the token MAC

The token deployment used `SHA256(secret || data)` as a MAC. Because of the hash construction, an attacker could extend the message and create a valid tag without knowing the secret.

SECS does not construct authentication by simply concatenating a secret with a message and hashing it. It uses digital signatures for non-repudiation and AES-GCM for authenticated encryption.

---

### 5. RSA shared-prime key generation

The RSA deployment generated keys using insufficient randomness, causing two devices to share a prime factor. An attacker could use a GCD calculation to recover a private key.

SECS assumes that signing and key-exchange private keys are generated using a cryptographically secure random number generator and are kept secret. Keys are also associated with identities through certificates.

---

### 6. Timing side channel

The timing deployment compared secrets using an early-exit comparison, leaking information through execution time.

SECS does not use a byte-by-byte early-exit comparison to authenticate the contract. Authentication is performed using cryptographic signature and AEAD verification algorithms designed for this purpose.

---

# 7. Main assumptions and limitations

The security of SECS is conditional and depends on several trusted components.

The CA must correctly authenticate identities and must not issue certificates to attackers.

Private signing keys must remain secret. If Alice's private key is stolen, an attacker could create signatures that appear to originate from Alice.

Similarly, if Bob's private key is compromised, an attacker could create fraudulent receipts.

The protocol also assumes that the cryptographic algorithms remain secure and are implemented correctly.

Finally, signed evidence must be retained. A signature is useful as evidence only if the parties preserve the signed contract, receipt, certificates, and relevant protocol metadata.

Therefore, SECS does not provide unconditional security. Its guarantees depend on the cryptographic primitives, correct key management, certificate validation, and preservation of the resulting evidence.

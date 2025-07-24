# Advanced Topics

* **Message Integrity & Authentication**: How HMAC is used for optional verification.
* **Salt & Key Management**: Generating and using salts, recommendations for secure passphrase management.

## HMAC Verification

When enabled, tzEnc2 uses HMAC-SHA256 to add a cryptographic digest to every encrypted message. This digest, computed with a secret passphrase, ensures that the encrypted data has not been tampered with and originated from someone who knows the digest passphrase. During decryption, the HMAC is recomputed and compared against the stored value; if it does not match, the data is rejected and an error is raised.

## Salt Generation

* **What is a salt?**
  A *salt* is a random value that is combined with your password before generating any cryptographic keys. This makes it much harder for attackers to use precomputed tables (rainbow tables) or find password collisions.

* **How is the salt generated?**
  In tzEnc2, every time you encrypt something, a new random 16-byte (128-bit) salt is created:

  ```python
  def generate_salt():
      return secrets.token_bytes(16)  # 16 bytes = 128 bits
  ```

  * This salt is unique **per encryption** and is stored as part of the encrypted output.

## Key Derivation (Password-Based Key Derivation)

* **How are keys generated?**

  * Your password and the random salt are combined using [Argon2id](https://datatracker.ietf.org/doc/html/rfc9106), a memory-hard key derivation function designed to resist brute-force and GPU attacks.
  * This process derives all the cryptographic "key materials" used by the algorithm:

    * The seed for the grid,
    * Any numbers used for grid setup,
    * Any AES keys (if needed internally).
  * All keys are **deterministically** generated from your password + salt + (sometimes a passphrase for the digest, if used).

  Example from your code:

  ```python
  key_materials = generate_multiple_keys(
      password=password,
      salt=salt,
      bits=ARGON2ID["BITS"],
      key_count=3
  )
  ```

* **Why do we use salt?**

  * So the *same* password never produces the same keys twice.
  * To ensure that identical messages encrypted with the same password result in completely different encrypted output each time.

## Keys Are Not Stored or Transmitted

* **Are the keys ever saved or sent?**
  **No.**
  The cryptographic keys (derived from your password + salt) are:

  * **Never stored on disk** (except as volatile memory during encryption/decryption).
  * **Never transmitted** in the output or over the network.
  * Only the *random salt* (which is not secret) is stored in the output to enable decryption later.

## What Happens if the Password is Lost?

* **If you forget your password:**
  There is **no automated way to recover your data**.

  * Even the project author or system admin cannot help you recover it.
  * The cryptographic keys cannot be recomputed without the exact password and the original salt.
  * This is by design and is essential for security.

* **If the output file (ciphertext) is lost or corrupted:**
  Data cannot be recovered.

* **If the salt in the output is altered or lost:**
  The password will produce the *wrong* keys, so decryption will fail.

## Summary Key Management & Salt

> * Every encryption uses a new, random 16-byte salt, stored with the encrypted data.
> * All cryptographic keys are **derived on demand** using your password (and optionally a digest passphrase) plus this salt, via the Argon2id KDF.
> * **Keys are never saved or sent anywhere.** Only the salt (not secret) is included in the output.
> * If you lose your password (or, for HMAC verification, your digest passphrase), your data **cannot** be decrypted. __There is no recovery, backdoor, or override—by design__.
> * Always back up your passwords and passphrases securely.

```plaintext
[User Password] + [Random Salt] ──> [Argon2id] ──> [Derived Keys]
      │                                │
      └──> (Password never saved)      │
                          │            │
[Salt] (stored in output) ┘            └──> Used only in memory, never saved/transmitted
```

## Configuration Options

In the `config/config.json` file you will find some options. Do NOT touch these unless you know what you are doing. You can really screw up the encryption/decryption process here if you aren't careful. 

You can configure the argon2id parameters and the number of cores used in used for parallelization.

**NOTE**: IF you change the argon2id settings for encrypting you MUST use those same settings when attempting to decrypt. This controls how long it takes to process the keys that are generated to help prevent brute force attack and mismatched settings will generate mismatched keys which will fail to decrypt properly.

You can change the parallel count if you like to increase the speed of the encryption/decryption process or adjust to hardware requirements.  The chunk size is the number of tasks qued up at one time (the task pool), this is critical that it be tuned properly for your hardware.  IF it is too low, the encryption/decryption will take a long time, because you will lose out the performance of parallelization because the tasks are small and you will not benefit from parallelization.  IF it is too high, the decryption process may hang or crash your system because you are queuing up too many tasks at once.  For my testing (which was extensive but limited to my hardware) 50% of the available threads seemed to be optimal. The default settings are tuned for my hardware (i7-12700KF) with 12 Cores.

I have been tinkering with a script to automatically tune the parallel count and chunk size for you, but it is not yet ready for prime time.  I will update this page when I have it ready.

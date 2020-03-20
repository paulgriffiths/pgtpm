# pgtpm

Package pgtpm provides TPM (Trusted Platform Module) 2.0 utilities, including:

 * An implementation of crypto.Signer allowing a TPM-resident private key to
   be used for signing certificate requests, certificates, and certificate
   revocation lists, for TLS client and server authentication, etc.

 * Standalone implementations of the SP 800-108 key derivation function and
   the TPM 2.0 "make credential" operation, enabling a privacy CA to create
   encrypted credentials for activation by a TPM

 * An interface to the Microsoft TPM 2.0 Simulator which can be used with the
   github.com/google/go-tpm/tpm2 package

 * A public template allowing TPM 2.0 object public areas to be marshalled
   to/from a convenient JSON-encoding

 * Various types and constants from the TPM 2.0 specification and their string
   representations

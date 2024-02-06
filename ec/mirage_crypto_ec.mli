(** {1 Elliptic curve cryptography} *)

(** Mirage-crypto-ec implements public key cryptography with named elliptic
    curves. Ephemeral key exchanges with {{!Dh}Diffie-Hellman} and
    {{!Dsa}digital signatures (ECDSA)} are implemented.

    The arithmetic operations uses code generated by
    {{:https://github.com/mit-plv/fiat-crypto}fiat-crypto} which is proven to
    consume a constant amount of time, independent of the input values.
*)

type error = [
  | `Invalid_range
  | `Invalid_format
  | `Invalid_length
  | `Not_on_curve
  | `At_infinity
  | `Low_order
]
(** The type for errors. *)

val pp_error : Format.formatter -> error -> unit
(** Pretty printer for errors *)

exception Message_too_long
(** Raised if the provided message is too long for the curve. *)

(** Diffie-Hellman key exchange. *)
module type Dh = sig

  type secret
  (** Type for private keys. *)

  val secret_of_cs : Cstruct.t -> (secret * Cstruct.t, error) result
  (** [secret_of_cs secret] decodes the provided buffer as {!secret}. May
      result in an error if the buffer had an invalid length or was not in
      bounds. *)

  val gen_key : ?g:Mirage_crypto_rng.g -> unit -> secret * Cstruct.t
  (** [gen_key ~g ()] generates a private and a public key for Ephemeral
      Diffie-Hellman. The returned key pair MUST only be used for a single
      key exchange.

      The generated private key is checked to be greater than zero and lower
      than the group order meaning the public key cannot be the point at
      inifinity. *)

  val key_exchange : secret -> Cstruct.t -> (Cstruct.t, error) result
  (** [key_exchange secret received_public_key] performs Diffie-Hellman key
      exchange using your secret and the data received from the other party.
      Returns the shared secret or an error if the received data is wrongly
      encoded, doesn't represent a point on the curve or represent the point
      at infinity.

      The shared secret is returned as is i.e. not stripped from leading 0x00
      bytes.

      The public key encoding is described
      {{:http://www.secg.org/sec1-v2.pdf}in SEC 1} from SECG. *)

  val secret_of_bytes : bytes -> (secret * bytes, error) result
  val gen_bytes_key : ?g:Mirage_crypto_rng.g -> unit -> secret * bytes
  val key_bytes_exchange : secret -> bytes -> (bytes, error) result
end

(** Digital signature algorithm. *)
module type Dsa = sig

  type priv
  (** The type for private keys. *)

  type pub
  (** The type for public keys. *)

  (** {2 Serialisation} *)

  val priv_of_cstruct : Cstruct.t -> (priv, error) result
  (** [priv_of_cstruct cs] decodes a private key from the buffer [cs]. If the
      provided data is invalid, an error is returned. *)

  val priv_to_cstruct : priv -> Cstruct.t
  (** [priv_to_cstruct p] encode the private key [p] to a buffer. *)

  val pub_of_cstruct : Cstruct.t -> (pub, error) result
  (** [pub_of_cstruct cs] decodes a public key from the buffer [cs]. If the
      provided data is invalid, an error is returned. *)

  val pub_to_cstruct : pub -> Cstruct.t
  (** [pub_to_cstruct p] encodes the public key [p] into a buffer. *)

  (** {2 Deriving the public key} *)

  val pub_of_priv : priv -> pub
  (** [pub_of_priv p] extracts the public key from the private key [p]. *)

  (** {2 Key generation} *)

  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
  (** [generate ~g ()] generates a key pair. *)

  (** {2 Cryptographic operations} *)

  val sign : key:priv -> ?k:Cstruct.t -> Cstruct.t -> Cstruct.t * Cstruct.t
  (** [sign ~key ~k digest] signs the message [digest] using the private
      [key]. The [digest] is not processed further - it should be the hash of
      the message to sign. If [k] is not provided, it is computed using the
      deterministic construction from RFC 6979. The result is a pair of [r]
      and [s].

      @raise Invalid_argument if [k] is not suitable or not in range.
      @raise Message_too_long if the bit size of [msg] exceeds the curve. *)

  val verify : key:pub -> Cstruct.t * Cstruct.t -> Cstruct.t -> bool
  (** [verify ~key (r, s) digest] verifies the signature [r, s] on the message
      [digest] with the public [key]. The return value is [true] if verification
      was successful, [false] otherwise. If the message has more bits than the
      group order, the result is false. *)

  (** [K_gen] can be instantiated over a hashing module to obtain an RFC6979
      compliant [k]-generator for that hash. *)
  module K_gen (H : Mirage_crypto.Hash.S) : sig

    val generate : key:priv -> Cstruct.t -> Cstruct.t
    (** [generate ~key digest] deterministically takes the given private key
        and message digest to a [k] suitable for seeding the signing process. *)

    val generate_bytes : key:priv -> bytes -> bytes
  end

  val priv_of_bytes : bytes -> (priv, error) result
  val priv_to_bytes : priv -> bytes
  val pub_of_bytes : bytes -> (pub, error) result
  val pub_to_bytes : pub -> bytes
  val sign_bytes : key:priv -> ?k:bytes -> bytes -> bytes * bytes
  val verify_bytes : key:pub -> bytes * bytes -> bytes -> bool

  val force_precomputation : unit -> unit
end

(** Elliptic curve with Diffie-Hellman and DSA. *)
module type Dh_dsa = sig

  (** Diffie-Hellman key exchange. *)
  module Dh : Dh

  (** Digital signature algorithm. *)
  module Dsa : Dsa
end

(** The NIST P-224 curve, also known as SECP224R1. *)
module P224 : Dh_dsa

(** The NIST P-256 curve, also known as SECP256R1. *)
module P256 : Dh_dsa

(** The NIST P-384 curve, also known as SECP384R1. *)
module P384 : Dh_dsa

(** The NIST P-521 curve, also known as SECP521R1. *)
module P521 : Dh_dsa

(** Curve 25519 Diffie-Hellman, also known as X25519. *)
module X25519 : Dh

(** Curve 25519 DSA, also known as Ed25519. *)
module Ed25519 : sig
  type priv
  (** The type for private keys. *)

  type pub
  (** The type for public keys. *)

  (** {2 Serialisation} *)

  val priv_of_cstruct : Cstruct.t -> (priv, error) result
  (** [priv_of_cstruct cs] decodes a private key from the buffer [cs]. If the
      provided data is invalid, an error is returned. *)

  val priv_to_cstruct : priv -> Cstruct.t
  (** [priv_to_cstruct p] encode the private key [p] to a buffer. *)

  val pub_of_cstruct : Cstruct.t -> (pub, error) result
  (** [pub_of_cstruct cs] decodes a public key from the buffer [cs]. If the
      provided data is invalid, an error is returned. *)

  val pub_to_cstruct : pub -> Cstruct.t
  (** [pub_to_cstruct p] encodes the public key [p] into a buffer. *)

  (** {2 Deriving the public key} *)

  val pub_of_priv : priv -> pub
  (** [pub_of_priv p] extracts the public key from the private key [p]. *)

  (** {2 Key generation} *)

  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
  (** [generate ~g ()] generates a key pair. *)

  (** {2 Cryptographic operations} *)

  val sign : key:priv -> Cstruct.t -> Cstruct.t
  (** [sign ~key msg] signs the message [msg] using the private [key]. The
      result is the concatenation of [r] and [s], as specified in RFC 8032. *)

  val verify : key:pub -> Cstruct.t -> msg:Cstruct.t -> bool
  (** [verify ~key signature msg] verifies the [signature] on the message
      [msg] with the public [key]. The return value is [true] if verification
      was successful, [false] otherwise. *)
end

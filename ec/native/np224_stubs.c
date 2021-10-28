#include "mirage_crypto.h"

#ifdef ARCH_64BIT
#include "np224_64.h"
#define LIMBS 4
#define WORD uint64_t
#define WORDSIZE 64
#else
#include "np224_32.h"
#define LIMBS 7
#define WORD uint32_t
#define WORDSIZE 32
#endif

#define LEN_PRIME 224
#define CURVE_DESCRIPTION fiat_np224

#include "inversion_template.h"

#include <caml/memory.h>

CAMLprim value mc_np224_inv(value out, value in)
{
	CAMLparam2(out, in);
	inversion((uint64_t *) Bytes_val(out), (uint64_t *) Bytes_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_np224_mul(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_np224_mul((uint64_t *) Bytes_val(out), (uint64_t *) Bytes_val(a), (uint64_t *) Bytes_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_np224_add(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_np224_add((uint64_t *) Bytes_val(out), (uint64_t *) Bytes_val(a), (uint64_t *) Bytes_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_np224_one(value out)
{
	CAMLparam1(out);
	fiat_np224_set_one((uint64_t *) Bytes_val(out));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_np224_from_bytes(value out, value in)
{
	CAMLparam2(out, in);
	fiat_np224_from_bytes((uint64_t *) Bytes_val(out), Bytes_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_np224_to_bytes(value out, value in)
{
	CAMLparam2(out, in);
	fiat_np224_to_bytes(Bytes_val(out), (uint64_t *) Bytes_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_np224_from_montgomery(value out, value in)
{
	CAMLparam2(out, in);
	fiat_np224_from_montgomery((uint64_t *) Bytes_val(out), (uint64_t *) Bytes_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_np224_to_montgomery(value out, value in)
{
	CAMLparam2(out, in);
	fiat_np224_to_montgomery((uint64_t *) Bytes_val(out), (uint64_t *) Bytes_val(in));
	CAMLreturn(Val_unit);
}

#include "mirage_crypto.h"

#ifdef ARCH_64BIT
#include "p224_64.h"
#define LIMBS 4
#define WORD uint64_t
#define WORDSIZE 64
#else
#include "p224_32.h"
#define LIMBS 7
#define WORD uint32_t
#define WORDSIZE 32
#endif

#define LEN_PRIME 224
#define CURVE_DESCRIPTION fiat_p224

#define FE_LENGTH 28

// Generator point, see https://neuromancer.sk/std/nist/P-224
static uint8_t gb_x[FE_LENGTH] = {0xb7, 0xe, 0xc, 0xbd, 0x6b, 0xb4, 0xbf, 0x7f, 0x32, 0x13, 0x90, 0xb9, 0x4a, 0x3, 0xc1, 0xd3, 0x56, 0xc2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xd6, 0x11, 0x5c, 0x1d, 0x21};
static uint8_t gb_y[FE_LENGTH] = {0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb, 0x4c, 0x22, 0xdf, 0xe6, 0xcd, 0x43, 0x75, 0xa0, 0x5a, 0x7, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99, 0x85, 0x0, 0x7e, 0x34};

#include "inversion_template.h"
#include "point_operations.h"

#include <caml/memory.h>

CAMLprim value mc_p224_sub(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_p224_sub((uint64_t *) Bytes_val(out), (uint64_t *) Bytes_val(a), (uint64_t *) Bytes_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_add(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_p224_add((uint64_t *) Bytes_val(out), (uint64_t *) Bytes_val(a), (uint64_t *) Bytes_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_mul(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_p224_mul((uint64_t *) Bytes_val(out), (uint64_t *) Bytes_val(a), (uint64_t *) Bytes_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_from_bytes(value out, value in)
{
	CAMLparam2(out, in);
	fiat_p224_from_bytes((uint64_t *) Bytes_val(out), Bytes_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_to_bytes(value out, value in)
{
	CAMLparam2(out, in);
	fiat_p224_to_bytes(Bytes_val(out), (uint64_t *) Bytes_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_sqr(value out, value in)
{
	CAMLparam2(out, in);
	fiat_p224_square((uint64_t *) Bytes_val(out), (uint64_t *) Bytes_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_from_montgomery(value x)
{
	CAMLparam1(x);
	WORD *l = (WORD *) Bytes_val(x);
	fiat_p224_from_montgomery(l, l);
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_to_montgomery(value x)
{
	CAMLparam1(x);
	WORD *l = (WORD *) Bytes_val(x);
	fiat_p224_to_montgomery(l, l);
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_nz(value x)
{
	CAMLparam1(x);
	CAMLreturn(Val_bool(fe_nz((uint64_t *) Bytes_val(x))));
}

CAMLprim value mc_p224_set_one(value x)
{
	CAMLparam1(x);
        fiat_p224_set_one((uint64_t *) Bytes_val(x));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_inv(value out, value in)
{
	CAMLparam2(out, in);
	inversion((uint64_t *) Bytes_val(out), (uint64_t *) Bytes_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_point_double(value out, value in)
{
	CAMLparam2(out, in);
	point_double(
		(uint64_t *) Bytes_val(Field(out, 0)),
		(uint64_t *) Bytes_val(Field(out, 1)),
		(uint64_t *) Bytes_val(Field(out, 2)),
		(uint64_t *) Bytes_val(Field(in, 0)),
		(uint64_t *) Bytes_val(Field(in, 1)),
		(uint64_t *) Bytes_val(Field(in, 2))
	);
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_point_add(value out, value p, value q)
{
	CAMLparam3(out, p, q);
	point_add(
		(uint64_t *) Bytes_val(Field(out, 0)),
		(uint64_t *) Bytes_val(Field(out, 1)),
		(uint64_t *) Bytes_val(Field(out, 2)),
		(uint64_t *) Bytes_val(Field(p, 0)),
		(uint64_t *) Bytes_val(Field(p, 1)),
		(uint64_t *) Bytes_val(Field(p, 2)),
		0,
		(uint64_t *) Bytes_val(Field(q, 0)),
		(uint64_t *) Bytes_val(Field(q, 1)),
		(uint64_t *) Bytes_val(Field(q, 2))
	);
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_select(value out, value bit, value t, value f)
{
	CAMLparam4(out, bit, t, f);
	fe_cmovznz(
		(uint64_t *) Bytes_val(out),
		Bool_val(bit),
		(uint64_t *) Bytes_val(f),
		(uint64_t *) Bytes_val(t)
	);
	CAMLreturn(Val_unit);
}

CAMLprim value mc_p224_scalar_mult_base(value out, value s)
{
    CAMLparam2(out, s);
    scalar_mult_base(
		(WORD *) Bytes_val(Field(out, 0)),
		(WORD *) Bytes_val(Field(out, 1)),
		(WORD *) Bytes_val(Field(out, 2)),
        (unsigned char *) Bytes_val(s),
        caml_string_length(s)
    );
    CAMLreturn(Val_unit);
}

CAMLprim void mc_p224_force_precomputation(void) {
    force_precomputation();
}

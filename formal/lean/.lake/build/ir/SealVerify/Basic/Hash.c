// Lean compiler output
// Module: SealVerify.Basic.Hash
// Imports: Init
#include <lean/lean.h>
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-label"
#elif defined(__GNUC__) && !defined(__CLANG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif
#ifdef __cplusplus
extern "C" {
#endif
LEAN_EXPORT uint8_t l_instDigestDecidableEq(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_instDigestRepr;
static lean_object* l_instDigestRepr___closed__1;
uint8_t lean_nat_dec_eq(lean_object*, lean_object*);
lean_object* l_instReprFin___rarg___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* l_instDigestDecidableEq___boxed(lean_object*, lean_object*);
LEAN_EXPORT uint8_t l_instDigestDecidableEq(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; 
x_3 = lean_nat_dec_eq(x_1, x_2);
return x_3;
}
}
LEAN_EXPORT lean_object* l_instDigestDecidableEq___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
uint8_t x_3; lean_object* x_4; 
x_3 = l_instDigestDecidableEq(x_1, x_2);
lean_dec(x_2);
lean_dec(x_1);
x_4 = lean_box(x_3);
return x_4;
}
}
static lean_object* _init_l_instDigestRepr___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_alloc_closure((void*)(l_instReprFin___rarg___boxed), 2, 0);
return x_1;
}
}
static lean_object* _init_l_instDigestRepr() {
_start:
{
lean_object* x_1; 
x_1 = l_instDigestRepr___closed__1;
return x_1;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_SealVerify_Basic_Hash(uint8_t builtin, lean_object* w) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l_instDigestRepr___closed__1 = _init_l_instDigestRepr___closed__1();
lean_mark_persistent(l_instDigestRepr___closed__1);
l_instDigestRepr = _init_l_instDigestRepr();
lean_mark_persistent(l_instDigestRepr);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif

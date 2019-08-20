/******************************************************************************
 * trigger-cfi-failure.c
 * 
 * Intentionally trigger a CFI failure to check if CFI checks are working.
 */

#include <xen/trigger-cfi-failure.h>
#include <xen/init.h>
#include <xen/lib.h>

static char __initdata cfi_crash_type[5] = "";
string_param("cfi-crash", cfi_crash_type);

static void noreturn __init noinline do_bad_call(void)
{
    // NB: maybe_do_cfi_crash has CFI labels in it for return sites. This
    // offset needs to be into a bundle without a CFI label.
    RELOC_HIDE(&maybe_do_cfi_crash, 0x62)();
    unreachable(); // Xen should have crashed
}

static void __init noinline do_bad_ret(void)
{
    long _dummy;

    // Get the address of the return address.
    // NB: This is super hacky and likely to break. Fortunately, this code is
    // only used for testing the CFI checks.
    uintptr_t *ra = (uintptr_t*)RELOC_HIDE(&_dummy, 8);

    ACCESS_ONCE(*ra) += 0x62;
}

void __init maybe_do_cfi_crash(void)
{
    if (strncmp(cfi_crash_type, "call", sizeof(cfi_crash_type)) == 0) {
        do_bad_call();
    } else if (strncmp(cfi_crash_type, "ret", sizeof(cfi_crash_type)) == 0) {
        do_bad_ret();
        unreachable(); // Xen should have crashed
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

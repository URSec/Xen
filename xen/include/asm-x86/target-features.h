#ifndef _ASM_X86_TARGET_FEATURES_H
#define _ASM_X86_TARGET_FEATURES_H

#define _XEN_TARGET_HAS_X86_FEATURE_FPU 1
#define _XEN_TARGET_HAS_X86_FEATURE_VME 1
#define _XEN_TARGET_HAS_X86_FEATURE_DE 1
#define _XEN_TARGET_HAS_X86_FEATURE_PSE 1
#define _XEN_TARGET_HAS_X86_FEATURE_TSC 1
#define _XEN_TARGET_HAS_X86_FEATURE_MSR 1
#define _XEN_TARGET_HAS_X86_FEATURE_PAE 1
#define _XEN_TARGET_HAS_X86_FEATURE_MCE 1
#define _XEN_TARGET_HAS_X86_FEATURE_CX8 1
#define _XEN_TARGET_HAS_X86_FEATURE_APIC 1
#define _XEN_TARGET_HAS_X86_FEATURE_SEP 1
#define _XEN_TARGET_HAS_X86_FEATURE_MTRR 1
#define _XEN_TARGET_HAS_X86_FEATURE_PGE 1
#define _XEN_TARGET_HAS_X86_FEATURE_MCA 1
#define _XEN_TARGET_HAS_X86_FEATURE_CMOV 1
#define _XEN_TARGET_HAS_X86_FEATURE_PAT 1
#define _XEN_TARGET_HAS_X86_FEATURE_PSE36 1
#define _XEN_TARGET_HAS_X86_FEATURE_CLFLUSH 1
#define _XEN_TARGET_HAS_X86_FEATURE_DS 1
#define _XEN_TARGET_HAS_X86_FEATURE_ACPI 1
#define _XEN_TARGET_HAS_X86_FEATURE_MMX 1
#define _XEN_TARGET_HAS_X86_FEATURE_FXSR 1
#define _XEN_TARGET_HAS_X86_FEATURE_SSE 1
#define _XEN_TARGET_HAS_X86_FEATURE_SSE2 1
#define _XEN_TARGET_HAS_X86_FEATURE_SS 1
#define _XEN_TARGET_HAS_X86_FEATURE_HTT 1
#define _XEN_TARGET_HAS_X86_FEATURE_TM1 1
#define _XEN_TARGET_HAS_X86_FEATURE_PBE 1
#define _XEN_TARGET_HAS_X86_FEATURE_SSE3 1
#ifdef __PCLMUL__
#define _XEN_TARGET_HAS_X86_FEATURE_PCLMULQDQ __PCLMUL__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_PCLMULQDQ 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_DTES64 1
#define _XEN_TARGET_HAS_X86_FEATURE_MONITOR 1
#define _XEN_TARGET_HAS_X86_FEATURE_DSCPL 1
#define _XEN_TARGET_HAS_X86_FEATURE_VMX 1
#define _XEN_TARGET_HAS_X86_FEATURE_SMX 1
#define _XEN_TARGET_HAS_X86_FEATURE_EIST 1
#define _XEN_TARGET_HAS_X86_FEATURE_TM2 1
#ifdef __SSSE3__
#define _XEN_TARGET_HAS_X86_FEATURE_SSSE3 __SSSE3__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_SSSE3 0
#endif
#ifdef __FMA__
#define _XEN_TARGET_HAS_X86_FEATURE_FMA __FMA__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_FMA 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_CX16 1
#define _XEN_TARGET_HAS_X86_FEATURE_XTPR 1
#define _XEN_TARGET_HAS_X86_FEATURE_PDCM 1
#define _XEN_TARGET_HAS_X86_FEATURE_PCID 1
#define _XEN_TARGET_HAS_X86_FEATURE_DCA 0
#ifdef __SSE4_1__
#define _XEN_TARGET_HAS_X86_FEATURE_SSE4_1 __SSE4_1__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_SSE4_1 0
#endif
#ifdef _SSE4_2__
#define _XEN_TARGET_HAS_X86_FEATURE_SSE4_2 _SSE4_2__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_SSE4_2 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_X2APIC 1
#ifdef __MOVBE__
#define _XEN_TARGET_HAS_X86_FEATURE_MOVBE __MOVBE__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_MOVBE 0
#endif
#ifdef __POPCNT__
#define _XEN_TARGET_HAS_X86_FEATURE_POPCNT __POPCNT__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_POPCNT 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_TSC_DEADLINE 1
#ifdef __AES__
#define _XEN_TARGET_HAS_X86_FEATURE_AESNI __AES__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AESNI 0
#endif
#ifdef __XSAVE__
#define _XEN_TARGET_HAS_X86_FEATURE_XSAVE __XSAVE__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_XSAVE 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_OSXSAVE 1
#ifdef __AVX__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX __AVX__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX 0
#endif
#ifdef __F16C__
#define _XEN_TARGET_HAS_X86_FEATURE_F16C __F16C__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_F16C 0
#endif
#ifdef __RDRAND__
#define _XEN_TARGET_HAS_X86_FEATURE_RDRAND __RDRAND__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_RDRAND 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_HYPERVISOR 0
#define _XEN_TARGET_HAS_X86_FEATURE_SYSCALL 1
#define _XEN_TARGET_HAS_X86_FEATURE_NX 1
#define _XEN_TARGET_HAS_X86_FEATURE_MMXEXT 0
#define _XEN_TARGET_HAS_X86_FEATURE_FFXSR 1
#define _XEN_TARGET_HAS_X86_FEATURE_PAGE1GB 1
#define _XEN_TARGET_HAS_X86_FEATURE_RDTSCP 1
#define _XEN_TARGET_HAS_X86_FEATURE_LM 1
#define _XEN_TARGET_HAS_X86_FEATURE_3DNOWEXT 0
#define _XEN_TARGET_HAS_X86_FEATURE_3DNOW 0
#define _XEN_TARGET_HAS_X86_FEATURE_LAHF_LM 1
#define _XEN_TARGET_HAS_X86_FEATURE_CMP_LEGACY 0
#define _XEN_TARGET_HAS_X86_FEATURE_SVM 0
#define _XEN_TARGET_HAS_X86_FEATURE_EXTAPIC 0
#define _XEN_TARGET_HAS_X86_FEATURE_CR8_LEGACY 0
#define _XEN_TARGET_HAS_X86_FEATURE_ABM 1
#define _XEN_TARGET_HAS_X86_FEATURE_SSE4A 0
#define _XEN_TARGET_HAS_X86_FEATURE_MISALIGNSSE 0
#define _XEN_TARGET_HAS_X86_FEATURE_3DNOWPREFETCH 1
#define _XEN_TARGET_HAS_X86_FEATURE_OSVW 0
#define _XEN_TARGET_HAS_X86_FEATURE_IBS 0
#define _XEN_TARGET_HAS_X86_FEATURE_XOP 0
#define _XEN_TARGET_HAS_X86_FEATURE_SKINIT 0
#define _XEN_TARGET_HAS_X86_FEATURE_WDT 0
#define _XEN_TARGET_HAS_X86_FEATURE_LWP 0
#ifdef __FMA4__
#define _XEN_TARGET_HAS_X86_FEATURE_FMA4 __FMA4__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_FMA4 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_NODEID_MSR 0
#define _XEN_TARGET_HAS_X86_FEATURE_TBM 1
#define _XEN_TARGET_HAS_X86_FEATURE_TOPOEXT 1
#define _XEN_TARGET_HAS_X86_FEATURE_DBEXT 1
#define _XEN_TARGET_HAS_X86_FEATURE_MONITORX 1
#ifdef __XSAVEOPT__
#define _XEN_TARGET_HAS_X86_FEATURE_XSAVEOPT __XSAVEOPT__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_XSAVEOPT 0
#endif
#ifdef __XSAVEC__
#define _XEN_TARGET_HAS_X86_FEATURE_XSAVEC __XSAVEC__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_XSAVEC 0
#endif
#ifdef __XSAVE__
#define _XEN_TARGET_HAS_X86_FEATURE_XGETBV1 __XSAVE__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_XGETBV1 0
#endif
#ifdef __XSAVES__
#define _XEN_TARGET_HAS_X86_FEATURE_XSAVES __XSAVES__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_XSAVES 0
#endif
#ifdef __FSGSBASE__
#define _XEN_TARGET_HAS_X86_FEATURE_FSGSBASE __FSGSBASE__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_FSGSBASE 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_TSC_ADJUST 1
#ifdef __SGX__
#define _XEN_TARGET_HAS_X86_FEATURE_SGX __SGX__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_SGX 0
#endif
#ifdef __BMI__
#define _XEN_TARGET_HAS_X86_FEATURE_BMI1 __BMI__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_BMI1 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_HLE 1
#ifdef __AVX2__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX2 __AVX2__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX2 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_FDP_EXCP_ONLY 0
#define _XEN_TARGET_HAS_X86_FEATURE_SMEP 1
#ifdef __BMI2__
#define _XEN_TARGET_HAS_X86_FEATURE_BMI2 __BMI2__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_BMI2 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_ERMS 1
#ifdef __INVPCID__
#define _XEN_TARGET_HAS_X86_FEATURE_INVPCID __INVPCID__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_INVPCID 0
#endif
#ifdef __RTM__
#define _XEN_TARGET_HAS_X86_FEATURE_RTM __RTM__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_RTM 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_PQM 0
#define _XEN_TARGET_HAS_X86_FEATURE_NO_FPU_SEL 0
#ifdef __MPX__
#define _XEN_TARGET_HAS_X86_FEATURE_MPX __MPX__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_MPX 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_PQE 0
#ifdef __AVX512F__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512F __AVX512F__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512F 0
#endif
#ifdef __AVX512DQ__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512DQ __AVX512DQ__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512DQ 0
#endif
#ifdef __RDSEED__
#define _XEN_TARGET_HAS_X86_FEATURE_RDSEED __RDSEED__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_RDSEED 0
#endif
#ifdef __ADX__
#define _XEN_TARGET_HAS_X86_FEATURE_ADX __ADX__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_ADX 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_SMAP 1
#ifdef __AVX512IFMA__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512IFMA __AVX512IFMA__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512IFMA 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_CLFLUSHOPT 1
#define _XEN_TARGET_HAS_X86_FEATURE_CLWB 0
#ifdef __AVX512PF__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512PF __AVX512PF__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512PF 0
#endif
#ifdef __AVX512ER__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512ER __AVX512ER__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512ER 0
#endif
#ifdef __AVX512CD__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512CD __AVX512CD__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512CD 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_SHA 0
#ifdef __AVX512BW__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512BW __AVX512BW__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512BW 0
#endif
#ifdef __AVX512VL__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512VL __AVX512VL__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512VL 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_PREFETCHWT1 0
#ifdef __AVX512VBMI__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512VBMI __AVX512VBMI__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512VBMI 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_UMIP 0
#define _XEN_TARGET_HAS_X86_FEATURE_PKU 0
#define _XEN_TARGET_HAS_X86_FEATURE_OSPKE 0
#ifdef __VPOPCNTDQ__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512_VPOPCNTDQ __VPOPCNTDQ__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512_VPOPCNTDQ 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_RDPID 0
#define _XEN_TARGET_HAS_X86_FEATURE_ITSC 0
#define _XEN_TARGET_HAS_X86_FEATURE_EFRO 0
#define _XEN_TARGET_HAS_X86_FEATURE_CLZERO 0
#define _XEN_TARGET_HAS_X86_FEATURE_IBPB 0
#ifdef __AVX512_4VNNIW__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512_4VNNIW __AVX512_4VNNIW__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512_4VNNIW 0
#endif
#ifdef __AVX512_4FMAPS__
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512_4FMAPS __AVX512_4FMAPS__
#else
#define _XEN_TARGET_HAS_X86_FEATURE_AVX512_4FMAPS 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_CONSTANT_TSC 1
#define _XEN_TARGET_HAS_X86_FEATURE_NONSTOP_TSC 1
#define _XEN_TARGET_HAS_X86_FEATURE_ARAT 1
#define _XEN_TARGET_HAS_X86_FEATURE_ARCH_PERFMON 1
#define _XEN_TARGET_HAS_X86_FEATURE_TSC_RELIABLE 0
#define _XEN_TARGET_HAS_X86_FEATURE_XTOPOLOGY 1
#define _XEN_TARGET_HAS_X86_FEATURE_CPUID_FAULTING 1
#define _XEN_TARGET_HAS_X86_FEATURE_CLFLUSH_MONITOR 0
#define _XEN_TARGET_HAS_X86_FEATURE_APERFMPERF 1
#define _XEN_TARGET_HAS_X86_FEATURE_MFENCE_RDTSC 1
#define _XEN_TARGET_HAS_X86_FEATURE_XEN_SMEP 1
#define _XEN_TARGET_HAS_X86_FEATURE_XEN_SMAP 1
#if 0
#define _XEN_TARGET_HAS_X86_FEATURE_IBRSB 1
#define _XEN_TARGET_HAS_X86_FEATURE_STIBP 1
#define _XEN_TARGET_HAS_X86_FEATURE_L1D_FLUSH 1
#define _XEN_TARGET_HAS_X86_FEATURE_ARCH_CAPS 1
#define _XEN_TARGET_HAS_X86_FEATURE_SSBD 1
#define _XEN_TARGET_HAS_X86_FEATURE_SC_MSR_PV 1
#define _XEN_TARGET_HAS_X86_FEATURE_SC_MSR_HVM 1
#define _XEN_TARGET_HAS_X86_FEATURE_SC_RSB_PV 1
#define _XEN_TARGET_HAS_X86_FEATURE_SC_RSB_HVM 1
#define _XEN_TARGET_HAS_X86_FEATURE_SC_MSR_IDLE 1
#else
#define _XEN_TARGET_HAS_X86_FEATURE_IBRSB 0
#define _XEN_TARGET_HAS_X86_FEATURE_STIBP 0
#define _XEN_TARGET_HAS_X86_FEATURE_L1D_FLUSH 0
#define _XEN_TARGET_HAS_X86_FEATURE_ARCH_CAPS 0
#define _XEN_TARGET_HAS_X86_FEATURE_SSBD 0
#define _XEN_TARGET_HAS_X86_FEATURE_SC_MSR_PV 0
#define _XEN_TARGET_HAS_X86_FEATURE_SC_MSR_HVM 0
#define _XEN_TARGET_HAS_X86_FEATURE_SC_RSB_PV 0
#define _XEN_TARGET_HAS_X86_FEATURE_SC_RSB_HVM 0
#define _XEN_TARGET_HAS_X86_FEATURE_SC_MSR_IDLE 0
#endif
#define _XEN_TARGET_HAS_X86_FEATURE_XEN_LBR 1

#ifdef __ASSEMBLY__

.set XEN_TARGET_HAS_X86_FEATURE_FPU, _XEN_TARGET_HAS_X86_FEATURE_FPU
.set XEN_TARGET_HAS_X86_FEATURE_VME, _XEN_TARGET_HAS_X86_FEATURE_VME
.set XEN_TARGET_HAS_X86_FEATURE_DE, _XEN_TARGET_HAS_X86_FEATURE_DE
.set XEN_TARGET_HAS_X86_FEATURE_PSE, _XEN_TARGET_HAS_X86_FEATURE_PSE
.set XEN_TARGET_HAS_X86_FEATURE_TSC, _XEN_TARGET_HAS_X86_FEATURE_TSC
.set XEN_TARGET_HAS_X86_FEATURE_MSR, _XEN_TARGET_HAS_X86_FEATURE_MSR
.set XEN_TARGET_HAS_X86_FEATURE_PAE, _XEN_TARGET_HAS_X86_FEATURE_PAE
.set XEN_TARGET_HAS_X86_FEATURE_MCE, _XEN_TARGET_HAS_X86_FEATURE_MCE
.set XEN_TARGET_HAS_X86_FEATURE_CX8, _XEN_TARGET_HAS_X86_FEATURE_CX8
.set XEN_TARGET_HAS_X86_FEATURE_APIC, _XEN_TARGET_HAS_X86_FEATURE_APIC
.set XEN_TARGET_HAS_X86_FEATURE_SEP, _XEN_TARGET_HAS_X86_FEATURE_SEP
.set XEN_TARGET_HAS_X86_FEATURE_MTRR, _XEN_TARGET_HAS_X86_FEATURE_MTRR
.set XEN_TARGET_HAS_X86_FEATURE_PGE, _XEN_TARGET_HAS_X86_FEATURE_PGE
.set XEN_TARGET_HAS_X86_FEATURE_MCA, _XEN_TARGET_HAS_X86_FEATURE_MCA
.set XEN_TARGET_HAS_X86_FEATURE_CMOV, _XEN_TARGET_HAS_X86_FEATURE_CMOV
.set XEN_TARGET_HAS_X86_FEATURE_PAT, _XEN_TARGET_HAS_X86_FEATURE_PAT
.set XEN_TARGET_HAS_X86_FEATURE_PSE36, _XEN_TARGET_HAS_X86_FEATURE_PSE36
.set XEN_TARGET_HAS_X86_FEATURE_CLFLUSH, _XEN_TARGET_HAS_X86_FEATURE_CLFLUSH
.set XEN_TARGET_HAS_X86_FEATURE_DS, _XEN_TARGET_HAS_X86_FEATURE_DS
.set XEN_TARGET_HAS_X86_FEATURE_ACPI, _XEN_TARGET_HAS_X86_FEATURE_ACPI
.set XEN_TARGET_HAS_X86_FEATURE_MMX, _XEN_TARGET_HAS_X86_FEATURE_MMX
.set XEN_TARGET_HAS_X86_FEATURE_FXSR, _XEN_TARGET_HAS_X86_FEATURE_FXSR
.set XEN_TARGET_HAS_X86_FEATURE_SSE, _XEN_TARGET_HAS_X86_FEATURE_SSE
.set XEN_TARGET_HAS_X86_FEATURE_SSE2, _XEN_TARGET_HAS_X86_FEATURE_SSE2
.set XEN_TARGET_HAS_X86_FEATURE_SS, _XEN_TARGET_HAS_X86_FEATURE_SS
.set XEN_TARGET_HAS_X86_FEATURE_HTT, _XEN_TARGET_HAS_X86_FEATURE_HTT
.set XEN_TARGET_HAS_X86_FEATURE_TM1, _XEN_TARGET_HAS_X86_FEATURE_TM1
.set XEN_TARGET_HAS_X86_FEATURE_PBE, _XEN_TARGET_HAS_X86_FEATURE_PBE
.set XEN_TARGET_HAS_X86_FEATURE_SSE3, _XEN_TARGET_HAS_X86_FEATURE_SSE3
.set XEN_TARGET_HAS_X86_FEATURE_PCLMULQDQ, _XEN_TARGET_HAS_X86_FEATURE_PCLMULQDQ
.set XEN_TARGET_HAS_X86_FEATURE_DTES64, _XEN_TARGET_HAS_X86_FEATURE_DTES64
.set XEN_TARGET_HAS_X86_FEATURE_MONITOR, _XEN_TARGET_HAS_X86_FEATURE_MONITOR
.set XEN_TARGET_HAS_X86_FEATURE_DSCPL, _XEN_TARGET_HAS_X86_FEATURE_DSCPL
.set XEN_TARGET_HAS_X86_FEATURE_VMX, _XEN_TARGET_HAS_X86_FEATURE_VMX
.set XEN_TARGET_HAS_X86_FEATURE_SMX, _XEN_TARGET_HAS_X86_FEATURE_SMX
.set XEN_TARGET_HAS_X86_FEATURE_EIST, _XEN_TARGET_HAS_X86_FEATURE_EIST
.set XEN_TARGET_HAS_X86_FEATURE_TM2, _XEN_TARGET_HAS_X86_FEATURE_TM2
.set XEN_TARGET_HAS_X86_FEATURE_SSSE3, _XEN_TARGET_HAS_X86_FEATURE_SSSE3
.set XEN_TARGET_HAS_X86_FEATURE_FMA, _XEN_TARGET_HAS_X86_FEATURE_FMA
.set XEN_TARGET_HAS_X86_FEATURE_CX16, _XEN_TARGET_HAS_X86_FEATURE_CX16
.set XEN_TARGET_HAS_X86_FEATURE_XTPR, _XEN_TARGET_HAS_X86_FEATURE_XTPR
.set XEN_TARGET_HAS_X86_FEATURE_PDCM, _XEN_TARGET_HAS_X86_FEATURE_PDCM
.set XEN_TARGET_HAS_X86_FEATURE_PCID, _XEN_TARGET_HAS_X86_FEATURE_PCID
.set XEN_TARGET_HAS_X86_FEATURE_DCA, _XEN_TARGET_HAS_X86_FEATURE_DCA
.set XEN_TARGET_HAS_X86_FEATURE_SSE4_1, _XEN_TARGET_HAS_X86_FEATURE_SSE4_1
.set XEN_TARGET_HAS_X86_FEATURE_SSE4_2, _XEN_TARGET_HAS_X86_FEATURE_SSE4_2
.set XEN_TARGET_HAS_X86_FEATURE_X2APIC, _XEN_TARGET_HAS_X86_FEATURE_X2APIC
.set XEN_TARGET_HAS_X86_FEATURE_MOVBE, _XEN_TARGET_HAS_X86_FEATURE_MOVBE
.set XEN_TARGET_HAS_X86_FEATURE_POPCNT, _XEN_TARGET_HAS_X86_FEATURE_POPCNT
.set XEN_TARGET_HAS_X86_FEATURE_TSC_DEADLINE, _XEN_TARGET_HAS_X86_FEATURE_TSC_DEADLINE
.set XEN_TARGET_HAS_X86_FEATURE_AESNI, _XEN_TARGET_HAS_X86_FEATURE_AESNI
.set XEN_TARGET_HAS_X86_FEATURE_XSAVE, _XEN_TARGET_HAS_X86_FEATURE_XSAVE
.set XEN_TARGET_HAS_X86_FEATURE_OSXSAVE, _XEN_TARGET_HAS_X86_FEATURE_OSXSAVE
.set XEN_TARGET_HAS_X86_FEATURE_AVX, _XEN_TARGET_HAS_X86_FEATURE_AVX
.set XEN_TARGET_HAS_X86_FEATURE_F16C, _XEN_TARGET_HAS_X86_FEATURE_F16C
.set XEN_TARGET_HAS_X86_FEATURE_RDRAND, _XEN_TARGET_HAS_X86_FEATURE_RDRAND
.set XEN_TARGET_HAS_X86_FEATURE_HYPERVISOR, _XEN_TARGET_HAS_X86_FEATURE_HYPERVISOR
.set XEN_TARGET_HAS_X86_FEATURE_SYSCALL, _XEN_TARGET_HAS_X86_FEATURE_SYSCALL
.set XEN_TARGET_HAS_X86_FEATURE_NX, _XEN_TARGET_HAS_X86_FEATURE_NX
.set XEN_TARGET_HAS_X86_FEATURE_MMXEXT, _XEN_TARGET_HAS_X86_FEATURE_MMXEXT
.set XEN_TARGET_HAS_X86_FEATURE_FFXSR, _XEN_TARGET_HAS_X86_FEATURE_FFXSR
.set XEN_TARGET_HAS_X86_FEATURE_PAGE1GB, _XEN_TARGET_HAS_X86_FEATURE_PAGE1GB
.set XEN_TARGET_HAS_X86_FEATURE_RDTSCP, _XEN_TARGET_HAS_X86_FEATURE_RDTSCP
.set XEN_TARGET_HAS_X86_FEATURE_LM, _XEN_TARGET_HAS_X86_FEATURE_LM
.set XEN_TARGET_HAS_X86_FEATURE_3DNOWEXT, _XEN_TARGET_HAS_X86_FEATURE_3DNOWEXT
.set XEN_TARGET_HAS_X86_FEATURE_3DNOW, _XEN_TARGET_HAS_X86_FEATURE_3DNOW
.set XEN_TARGET_HAS_X86_FEATURE_LAHF_LM, _XEN_TARGET_HAS_X86_FEATURE_LAHF_LM
.set XEN_TARGET_HAS_X86_FEATURE_CMP_LEGACY, _XEN_TARGET_HAS_X86_FEATURE_CMP_LEGACY
.set XEN_TARGET_HAS_X86_FEATURE_SVM, _XEN_TARGET_HAS_X86_FEATURE_SVM
.set XEN_TARGET_HAS_X86_FEATURE_EXTAPIC, _XEN_TARGET_HAS_X86_FEATURE_EXTAPIC
.set XEN_TARGET_HAS_X86_FEATURE_CR8_LEGACY, _XEN_TARGET_HAS_X86_FEATURE_CR8_LEGACY
.set XEN_TARGET_HAS_X86_FEATURE_ABM, _XEN_TARGET_HAS_X86_FEATURE_ABM
.set XEN_TARGET_HAS_X86_FEATURE_SSE4A, _XEN_TARGET_HAS_X86_FEATURE_SSE4A
.set XEN_TARGET_HAS_X86_FEATURE_MISALIGNSSE, _XEN_TARGET_HAS_X86_FEATURE_MISALIGNSSE
.set XEN_TARGET_HAS_X86_FEATURE_3DNOWPREFETCH, _XEN_TARGET_HAS_X86_FEATURE_3DNOWPREFETCH
.set XEN_TARGET_HAS_X86_FEATURE_OSVW, _XEN_TARGET_HAS_X86_FEATURE_OSVW
.set XEN_TARGET_HAS_X86_FEATURE_IBS, _XEN_TARGET_HAS_X86_FEATURE_IBS
.set XEN_TARGET_HAS_X86_FEATURE_XOP, _XEN_TARGET_HAS_X86_FEATURE_XOP
.set XEN_TARGET_HAS_X86_FEATURE_SKINIT, _XEN_TARGET_HAS_X86_FEATURE_SKINIT
.set XEN_TARGET_HAS_X86_FEATURE_WDT, _XEN_TARGET_HAS_X86_FEATURE_WDT
.set XEN_TARGET_HAS_X86_FEATURE_LWP, _XEN_TARGET_HAS_X86_FEATURE_LWP
.set XEN_TARGET_HAS_X86_FEATURE_FMA4, _XEN_TARGET_HAS_X86_FEATURE_FMA4
.set XEN_TARGET_HAS_X86_FEATURE_NODEID_MSR, _XEN_TARGET_HAS_X86_FEATURE_NODEID_MSR
.set XEN_TARGET_HAS_X86_FEATURE_TBM, _XEN_TARGET_HAS_X86_FEATURE_TBM
.set XEN_TARGET_HAS_X86_FEATURE_TOPOEXT, _XEN_TARGET_HAS_X86_FEATURE_TOPOEXT
.set XEN_TARGET_HAS_X86_FEATURE_DBEXT, _XEN_TARGET_HAS_X86_FEATURE_DBEXT
.set XEN_TARGET_HAS_X86_FEATURE_MONITORX, _XEN_TARGET_HAS_X86_FEATURE_MONITORX
.set XEN_TARGET_HAS_X86_FEATURE_XSAVEOPT, _XEN_TARGET_HAS_X86_FEATURE_XSAVEOPT
.set XEN_TARGET_HAS_X86_FEATURE_XSAVEC, _XEN_TARGET_HAS_X86_FEATURE_XSAVEC
.set XEN_TARGET_HAS_X86_FEATURE_XGETBV1, _XEN_TARGET_HAS_X86_FEATURE_XGETBV1
.set XEN_TARGET_HAS_X86_FEATURE_XSAVES, _XEN_TARGET_HAS_X86_FEATURE_XSAVES
.set XEN_TARGET_HAS_X86_FEATURE_FSGSBASE, _XEN_TARGET_HAS_X86_FEATURE_FSGSBASE
.set XEN_TARGET_HAS_X86_FEATURE_TSC_ADJUST, _XEN_TARGET_HAS_X86_FEATURE_TSC_ADJUST
.set XEN_TARGET_HAS_X86_FEATURE_SGX, _XEN_TARGET_HAS_X86_FEATURE_SGX
.set XEN_TARGET_HAS_X86_FEATURE_BMI1, _XEN_TARGET_HAS_X86_FEATURE_BMI1
.set XEN_TARGET_HAS_X86_FEATURE_HLE, _XEN_TARGET_HAS_X86_FEATURE_HLE
.set XEN_TARGET_HAS_X86_FEATURE_AVX2, _XEN_TARGET_HAS_X86_FEATURE_AVX2
.set XEN_TARGET_HAS_X86_FEATURE_FDP_EXCP_ONLY, _XEN_TARGET_HAS_X86_FEATURE_FDP_EXCP_ONLY
.set XEN_TARGET_HAS_X86_FEATURE_SMEP, _XEN_TARGET_HAS_X86_FEATURE_SMEP
.set XEN_TARGET_HAS_X86_FEATURE_BMI2, _XEN_TARGET_HAS_X86_FEATURE_BMI2
.set XEN_TARGET_HAS_X86_FEATURE_ERMS, _XEN_TARGET_HAS_X86_FEATURE_ERMS
.set XEN_TARGET_HAS_X86_FEATURE_INVPCID, _XEN_TARGET_HAS_X86_FEATURE_INVPCID
.set XEN_TARGET_HAS_X86_FEATURE_RTM, _XEN_TARGET_HAS_X86_FEATURE_RTM
.set XEN_TARGET_HAS_X86_FEATURE_PQM, _XEN_TARGET_HAS_X86_FEATURE_PQM
.set XEN_TARGET_HAS_X86_FEATURE_NO_FPU_SEL, _XEN_TARGET_HAS_X86_FEATURE_NO_FPU_SEL
.set XEN_TARGET_HAS_X86_FEATURE_MPX, _XEN_TARGET_HAS_X86_FEATURE_MPX
.set XEN_TARGET_HAS_X86_FEATURE_PQE, _XEN_TARGET_HAS_X86_FEATURE_PQE
.set XEN_TARGET_HAS_X86_FEATURE_AVX512F, _XEN_TARGET_HAS_X86_FEATURE_AVX512F
.set XEN_TARGET_HAS_X86_FEATURE_AVX512DQ, _XEN_TARGET_HAS_X86_FEATURE_AVX512DQ
.set XEN_TARGET_HAS_X86_FEATURE_RDSEED, _XEN_TARGET_HAS_X86_FEATURE_RDSEED
.set XEN_TARGET_HAS_X86_FEATURE_ADX, _XEN_TARGET_HAS_X86_FEATURE_ADX
.set XEN_TARGET_HAS_X86_FEATURE_SMAP, _XEN_TARGET_HAS_X86_FEATURE_SMAP
.set XEN_TARGET_HAS_X86_FEATURE_AVX512IFMA, _XEN_TARGET_HAS_X86_FEATURE_AVX512IFMA
.set XEN_TARGET_HAS_X86_FEATURE_CLFLUSHOPT, _XEN_TARGET_HAS_X86_FEATURE_CLFLUSHOPT
.set XEN_TARGET_HAS_X86_FEATURE_CLWB, _XEN_TARGET_HAS_X86_FEATURE_CLWB
.set XEN_TARGET_HAS_X86_FEATURE_AVX512PF, _XEN_TARGET_HAS_X86_FEATURE_AVX512PF
.set XEN_TARGET_HAS_X86_FEATURE_AVX512ER, _XEN_TARGET_HAS_X86_FEATURE_AVX512ER
.set XEN_TARGET_HAS_X86_FEATURE_AVX512CD, _XEN_TARGET_HAS_X86_FEATURE_AVX512CD
.set XEN_TARGET_HAS_X86_FEATURE_SHA, _XEN_TARGET_HAS_X86_FEATURE_SHA
.set XEN_TARGET_HAS_X86_FEATURE_AVX512BW, _XEN_TARGET_HAS_X86_FEATURE_AVX512BW
.set XEN_TARGET_HAS_X86_FEATURE_AVX512VL, _XEN_TARGET_HAS_X86_FEATURE_AVX512VL
.set XEN_TARGET_HAS_X86_FEATURE_PREFETCHWT1, _XEN_TARGET_HAS_X86_FEATURE_PREFETCHWT1
.set XEN_TARGET_HAS_X86_FEATURE_AVX512VBMI, _XEN_TARGET_HAS_X86_FEATURE_AVX512VBMI
.set XEN_TARGET_HAS_X86_FEATURE_UMIP, _XEN_TARGET_HAS_X86_FEATURE_UMIP
.set XEN_TARGET_HAS_X86_FEATURE_PKU, _XEN_TARGET_HAS_X86_FEATURE_PKU
.set XEN_TARGET_HAS_X86_FEATURE_OSPKE, _XEN_TARGET_HAS_X86_FEATURE_OSPKE
.set XEN_TARGET_HAS_X86_FEATURE_AVX512_VPOPCNTDQ, _XEN_TARGET_HAS_X86_FEATURE_AVX512_VPOPCNTDQ
.set XEN_TARGET_HAS_X86_FEATURE_RDPID, _XEN_TARGET_HAS_X86_FEATURE_RDPID
.set XEN_TARGET_HAS_X86_FEATURE_ITSC, _XEN_TARGET_HAS_X86_FEATURE_ITSC
.set XEN_TARGET_HAS_X86_FEATURE_EFRO, _XEN_TARGET_HAS_X86_FEATURE_EFRO
.set XEN_TARGET_HAS_X86_FEATURE_CLZERO, _XEN_TARGET_HAS_X86_FEATURE_CLZERO
.set XEN_TARGET_HAS_X86_FEATURE_IBPB, _XEN_TARGET_HAS_X86_FEATURE_IBPB
.set XEN_TARGET_HAS_X86_FEATURE_AVX512_4VNNIW, _XEN_TARGET_HAS_X86_FEATURE_AVX512_4VNNIW
.set XEN_TARGET_HAS_X86_FEATURE_AVX512_4FMAPS, _XEN_TARGET_HAS_X86_FEATURE_AVX512_4FMAPS
.set XEN_TARGET_HAS_X86_FEATURE_IBRSB, _XEN_TARGET_HAS_X86_FEATURE_IBRSB
.set XEN_TARGET_HAS_X86_FEATURE_STIBP, _XEN_TARGET_HAS_X86_FEATURE_STIBP
.set XEN_TARGET_HAS_X86_FEATURE_L1D_FLUSH, _XEN_TARGET_HAS_X86_FEATURE_L1D_FLUSH
.set XEN_TARGET_HAS_X86_FEATURE_ARCH_CAPS, _XEN_TARGET_HAS_X86_FEATURE_ARCH_CAPS
.set XEN_TARGET_HAS_X86_FEATURE_SSBD, _XEN_TARGET_HAS_X86_FEATURE_SSBD
.set XEN_TARGET_HAS_X86_FEATURE_CONSTANT_TSC, _XEN_TARGET_HAS_X86_FEATURE_CONSTANT_TSC
.set XEN_TARGET_HAS_X86_FEATURE_NONSTOP_TSC, _XEN_TARGET_HAS_X86_FEATURE_NONSTOP_TSC
.set XEN_TARGET_HAS_X86_FEATURE_ARAT, _XEN_TARGET_HAS_X86_FEATURE_ARAT
.set XEN_TARGET_HAS_X86_FEATURE_ARCH_PERFMON, _XEN_TARGET_HAS_X86_FEATURE_ARCH_PERFMON
.set XEN_TARGET_HAS_X86_FEATURE_TSC_RELIABLE, _XEN_TARGET_HAS_X86_FEATURE_TSC_RELIABLE
.set XEN_TARGET_HAS_X86_FEATURE_XTOPOLOGY, _XEN_TARGET_HAS_X86_FEATURE_XTOPOLOGY
.set XEN_TARGET_HAS_X86_FEATURE_CPUID_FAULTING, _XEN_TARGET_HAS_X86_FEATURE_CPUID_FAULTING
.set XEN_TARGET_HAS_X86_FEATURE_CLFLUSH_MONITOR, _XEN_TARGET_HAS_X86_FEATURE_CLFLUSH_MONITOR
.set XEN_TARGET_HAS_X86_FEATURE_APERFMPERF, _XEN_TARGET_HAS_X86_FEATURE_APERFMPERF
.set XEN_TARGET_HAS_X86_FEATURE_MFENCE_RDTSC, _XEN_TARGET_HAS_X86_FEATURE_MFENCE_RDTSC
.set XEN_TARGET_HAS_X86_FEATURE_XEN_SMEP, _XEN_TARGET_HAS_X86_FEATURE_XEN_SMEP
.set XEN_TARGET_HAS_X86_FEATURE_XEN_SMAP, _XEN_TARGET_HAS_X86_FEATURE_XEN_SMAP
.set XEN_TARGET_HAS_X86_FEATURE_SC_MSR_PV, _XEN_TARGET_HAS_X86_FEATURE_SC_MSR_PV
.set XEN_TARGET_HAS_X86_FEATURE_SC_MSR_HVM, _XEN_TARGET_HAS_X86_FEATURE_SC_MSR_HVM
.set XEN_TARGET_HAS_X86_FEATURE_SC_RSB_PV, _XEN_TARGET_HAS_X86_FEATURE_SC_RSB_PV
.set XEN_TARGET_HAS_X86_FEATURE_SC_RSB_HVM, _XEN_TARGET_HAS_X86_FEATURE_SC_RSB_HVM
.set XEN_TARGET_HAS_X86_FEATURE_SC_MSR_IDLE, _XEN_TARGET_HAS_X86_FEATURE_SC_MSR_IDLE
.set XEN_TARGET_HAS_X86_FEATURE_XEN_LBR, _XEN_TARGET_HAS_X86_FEATURE_XEN_LBR

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_TARGET_FEATURES_H */

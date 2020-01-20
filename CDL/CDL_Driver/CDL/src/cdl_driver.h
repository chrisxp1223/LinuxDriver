//! Linux CDL driver - 2nd Generation.
/** \file
 *  \author Michael Floyd
 */

/** \if Copyright
 * Copyright 2013-2016 ADVANCED MICRO DEVICES, INC. All Rights Reserved.
 *
 * This software and any related documentation (the "Materials") are the
 * confidential proprietary information of AMD. Unless otherwise provided
 * in a software agreement specifically licensing the Materials, the Materials
 * are provided in confidence and may not be distributed, modified, or
 * reproduced in whole or in part by any means.
 *
 * LIMITATION OF LIABILITY: THE MATERIALS ARE PROVIDED "AS IS" WITHOUT ANY
 * EXPRESS OR IMPLIED WARRANTY OF ANY KIND, INCLUDING BUT NOT LIMITED TO
 * WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT, TITLE, FITNESS FOR ANY
 * PARTICULAR PURPOSE, OR WARRANTIES ARISING FORM CONDUCT, COURSE OF DEALING,
 * OR USAGE OF TRADE.  IN NO EVENT SHALL AMD OR ITS LICENSORS BE LIABLE FOR
 * ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF
 * PROFITS, BUSINESS INTERRUPTION, OR LOSS OF INFORMATION) ARISING OUT OF THE
 * USE OF OR INABILITY TO USE THE MATERIALS, EVEN IF AMD HAS BEEN ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.  BECAUSE SOME JURISDICTIONS PROHIBIT THE
 * EXCLUSION OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES,
 * THE ABOVE LIMITATION MAY NOT APPLY TO YOU.
 *
 * AMD does not assume any responsibility for any errors which may appear in the
 * Materials nor any responsibility to support or update the Materials.  AMD
 * retains the right to modify the Materials at any time, without notice,
 * and is not obligated to provide such modified Materials to you.
 *
 * NO SUPPORT OBLIGATION: AMD is not obligated to furnish, support, or make any
 * further information, software, technical information, know-how, or show-how
 * available to you.
 *
 * U.S. GOVERNMENT RESTRICTED RIGHTS: The Materials are provided with
 * "RESTRICTED RIGHTS." Use, duplication, or disclosure by the Government
 * is subject to the restrictions as set forth in FAR 52.227-14 and DFAR
 * 252.227-7013, et seq., or its successor.  Use of the Materials by the
 * Government constitutes acknowledgement of AMD's proprietary rights in them.
 * \endif
 */
/** */

/* just to clarify the structure this driver would access */
typedef gate_desc idt_desc;

/* to check vector range */
#define is_valid_vector(vector)                                         \
	((vector) >= 0 && (vector) <  NR_VECTORS)
#define is_exception_vector(vector)                                     \
	((vector) >= 0 && (vector) <  FIRST_EXTERNAL_VECTOR)
#define is_hwirq_vector(vector)                                         \
	((vector) >= FIRST_EXTERNAL_VECTOR  && (vector) < NR_VECTORS)

/* number of input arguments from the application (the diag suite) */
#define IARGS1          1
#define IARGS2          2
#define IARGS3          3
#define IARGS4          4
#define IARGS5          5
#define IARGS6          6
#define IARGS7          7
#define IARGS8          8

/* number of output arguments from the application (the diag suite) */
#define OARGS1          1
#define OARGS2          2
#define OARGS8          8

/* size of max. nodename in bytes */
#define MAX_NODENAME_LEN       16

#define NO_IRQ         -1

/* size of each input/output arguments from the application */
#define ARGSIZE (sizeof(uint64_t))

/* Flags in PTE */
#define PAGE_PRESENT        0x001
#define PAGE_RW             0x002
#define PAGE_USER           0x004
#define PAGE_PWT            0x008
#define PAGE_PCD            0x010
#define PAGE_ACCESSED       0x020
#define PAGE_DIRTY          0x040
#define PAGE_PAT            0x080
#define PAGE_GLOBAL         0x100   /* Global TLB entry */
#define PAGE_NX         (1UL<< 63)

#define halt()    asm volatile ("hlt")
#define sti()     asm volatile ("sti")
#define wbinvd()  asm volatile ("wbinvd")
#define stgi() asm volatile    ("stgi")
#define clgi() asm volatile    ("clgi")

#define HWRCR_SMM_LOCK_MASK 0x00000001

/* defines maximum number of CPUs supported by the driver */
#define MAX_NUM_CPUS     256

#define MAX_MSI_NUM_VECTORS 32

/* internal structure to hold interrupt/exception handler for the suite */
struct cdl_irq_desc {
   idt_desc idtdesc;

   void *handler;
   int   irq;
   char  name[MAX_NODENAME_LEN];
};

struct msr_passwd {
  uint32_t edi;
  uint32_t esi;
};

void *RESERVED = (void *)~0ull;
void *UNUSED   = NULL;

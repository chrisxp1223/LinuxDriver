# Makefile for the ubuntu driver.
# \author Anup Chakkingal

# Copyright 2013 ADVANCED MICRO DEVICES, INC. All Rights Reserved.
#
# This software and any related documentation (the "Materials") are the
# confidential proprietary information of AMD. Unless otherwise provided
# in a software agreement specifically licensing the Materials, the Materials
# are provided in confidence and may not be distributed, modified, or
# reproduced in whole or in part by any means.
#
# LIMITATION OF LIABILITY: THE MATERIALS ARE PROVIDED "AS IS" WITHOUT ANY
# EXPRESS OR IMPLIED WARRANTY OF ANY KIND, INCLUDING BUT NOT LIMITED TO
# WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT, TITLE, FITNESS FOR ANY
# PARTICULAR PURPOSE, OR WARRANTIES ARISING FORM CONDUCT, COURSE OF DEALING,
# OR USAGE OF TRADE.  IN NO EVENT SHALL AMD OR ITS LICENSORS BE LIABLE FOR
# ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF
# PROFITS, BUSINESS INTERRUPTION, OR LOSS OF INFORMATION) ARISING OUT OF THE
# USE OF OR INABILITY TO USE THE MATERIALS, EVEN IF AMD HAS BEEN ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGES.  BECAUSE SOME JURISDICTIONS PROHIBIT THE
# EXCLUSION OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES,
# THE ABOVE LIMITATION MAY NOT APPLY TO YOU.
#
# AMD does not assume any responsibility for any errors which may appear in the
# Materials nor any responsibility to support or update the Materials.  AMD
# retains the right to modify the Materials at any time, without notice,
# and is not obligated to provide such modified Materials to you.
#
# NO SUPPORT OBLIGATION: AMD is not obligated to furnish, support, or make any
# further information, software, technical information, know-how, or show-how
# available to you.
#
# U.S. GOVERNMENT RESTRICTED RIGHTS: The Materials are provided with
# "RESTRICTED RIGHTS." Use, duplication, or disclosure by the Government
# is subject to the restrictions as set forth in FAR 52.227-14 and DFAR
# 252.227-7013, et seq., or its successor.  Use of the Materials by the
# Government constitutes acknowledgement of AMD's proprietary rights in them.

PWD := $(shell pwd)
ifndef KVERSION
KVERSION := $(shell uname -r)
endif

SRC_DIR := src
ASM_DIR := asm
LIB_DIR := lib
KPR_DIR := kprobe

obj-m := CDL-Driver.o # amdkprobe.o
CDL-Driver-y := $(SRC_DIR)/$(ASM_DIR)/lowlevel.o $(SRC_DIR)/$(ASM_DIR)/amex-lowlevel.o $(SRC_DIR)/$(ASM_DIR)/translate.o $(SRC_DIR)/$(ASM_DIR)/cc6.o $(SRC_DIR)/$(ASM_DIR)/instructions.o
CDL-Driver-y += $(SRC_DIR)/cdl_driver.o
CDL-Driver-y += $(SRC_DIR)/$(LIB_DIR)/smi/smi.o
CDL-Driver-y += $(SRC_DIR)/$(LIB_DIR)/amex/amex.o
CDL-Driver-y += $(SRC_DIR)/$(LIB_DIR)/common/smep.o $(SRC_DIR)/$(LIB_DIR)/common/user-code.o # $(SRC_DIR)/$(LIB_DIR)/common/checkpoint.o $(SRC_DIR)/$(LIB_DIR)/common/bist.o
# amdkprobe-y := $(SRC_DIR)/$(KPR_DIR)/cdl_kprobe.o

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

install:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules_install

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

enum amd_ioctl_cmd {
	EXECUTE_WBINVD_INSTRUCTION = 1,
	READ_PVT_MSR,
	WRITE_PVT_MSR,
	RMW_PVT_MSR,
	PRE_SET_MEMORY_TYPE,
	HLT,
	HLT_IOPORT,
	READ_PCI_IOPORT,
	WRITE_PCI_IOPORT,
	RMW_PCI_IOPORT,
	DISABLE_TLBFLUSH_IPI,
	ENABLE_TLBFLUSH_IPI,
	CALL_AMEX_ENTRY,
	DISABLE_SCHEDULER,
	ENABLE_SCHEDULER,
	DISABLE_CURRENT_SCHEDULER,
	ENABLE_CURRENT_SCHEDULER,   /* 0x11 (17) */
	INSTALL_AMD_USER_CODE,
	CALL_AMD_USER_CODE,
	DELETE_AMD_USER_CODE,
	READ_CR4,
	WRITE_CR4,
	SET_IN_CR4,
	CLEAR_IN_CR4,
	IS_SMM_LOCKED,
	INSTALL_SMI_HANDLER,
	RESTORE_SMI_HANDLER,
	WRITE_SMM_BYTE,
	READ_SMM_BYTE,
	SEND_SMI,
	INSTALL_INTERRUPT_HANDLER,
	DISABLE_INTERRUPT_HANDLER,
	ENABLE_INTERRUPT_HANDLER,    /* 0x21 (33) */
	REMOVE_INTERRUPT_HANDLER,
	READ_INTERRUPT_DATA,
	WRITE_INTERRUPT_DATA,
	INTERRUPT_TEST,
	INVALIDATE_PAGE,
	INVALIDATE_TLB,
	INVALIDATE_CACHES,
	FLUSH_CACHE_LINE,
	READ_GS_BASE,
	READ_CR2,
	WRITE_CR2,
	READ_CR3,
	WRITE_CR3,
	STGI,
	CLGI,
	READ_CR8,                    /* 0x31 (49) */
	WRITE_CR8,
	GET_LINEAR_ADDRESS,
	GET_PHYSICAL_ADDRESS,
	RESERVE_VECTOR,
	FREE_VECTOR,
	GET_LAPIC_LINBASE,
	HARDLOCK,
	READ_USER_DATA,
	WRITE_USER_DATA,
	SEND_INT_ALL,
	SEND_INT_ALL_BUT_SELF,
	SEND_INT_MASK,
	EXECUTE_INVLPGB_INSTRUCTION,
	EXECUTE_TLBSYNC_INSTRUCTION,
	SET_PTE,
	RESERVE_MSI_VECTOR,
	FREE_MSI_VECTOR
};


#define IOC_MAGIC                                'q'
#define IOCTL_EXECUTE_WBINVD_INSTRUCTION         _IO(IOC_MAGIC, EXECUTE_WBINVD_INSTRUCTION)
#define IOCTL_READ_PVT_MSR                       _IOWR(IOC_MAGIC, READ_PVT_MSR, unsigned long)
#define IOCTL_WRITE_PVT_MSR                      _IOW(IOC_MAGIC, WRITE_PVT_MSR, unsigned long)
#define IOCTL_RMW_PVT_MSR                        _IOW(IOC_MAGIC, RMW_PVT_MSR, unsigned long)
#define IOCTL_PRE_SET_MEMORY_TYPE                _IOW(IOC_MAGIC, PRE_SET_MEMORY_TYPE, unsigned long)
#define IOCTL_HLT                                _IOW(IOC_MAGIC, HLT, unsigned long)
#define IOCTL_HLT_IOPORT                         _IOW(IOC_MAGIC, HLT_IOPORT, unsigned long)
#define IOCTL_READ_PCI_IOPORT                    _IOWR(IOC_MAGIC, READ_PCI_IOPORT, unsigned long)
#define IOCTL_WRITE_PCI_IOPORT                   _IOWR(IOC_MAGIC, WRITE_PCI_IOPORT, unsigned long)
#define IOCTL_RMW_PCI_IOPORT                     _IOWR(IOC_MAGIC, RMW_PCI_IOPORT, unsigned long)
#define IOCTL_CALL_AMEX_ENTRY                    _IOR(IOC_MAGIC, CALL_AMEX_ENTRY, unsigned long)
#define IOCTL_DISABLE_TLBFLUSH_IPI               _IO(IOC_MAGIC, DISABLE_TLBFLUSH_IPI)
#define IOCTL_ENABLE_TLBFLUSH_IPI                _IO(IOC_MAGIC, ENABLE_TLBFLUSH_IPI)
#define IOCTL_ENABLE_SCHEDULER                   _IO(IOC_MAGIC, ENABLE_SCHEDULER)
#define IOCTL_DISABLE_SCHEDULER                  _IO(IOC_MAGIC, DISABLE_SCHEDULER)
#define IOCTL_ENABLE_CURRENT_SCHEDULER           _IO(IOC_MAGIC, ENABLE_CURRENT_SCHEDULER)
#define IOCTL_DISABLE_CURRENT_SCHEDULER          _IO(IOC_MAGIC, DISABLE_CURRENT_SCHEDULER)
#define IOCTL_INSTALL_AMD_USER_CODE              _IOWR(IOC_MAGIC, INSTALL_AMD_USER_CODE, unsigned long)
#define IOCTL_CALL_AMD_USER_CODE                 _IOWR(IOC_MAGIC, CALL_AMD_USER_CODE, unsigned long)
#define IOCTL_DELETE_AMD_USER_CODE               _IOW(IOC_MAGIC, DELETE_AMD_USER_CODE, unsigned long)
#define IOCTL_READ_CR4                           _IOR(IOC_MAGIC, READ_CR4, unsigned long)
#define IOCTL_WRITE_CR4                          _IOW(IOC_MAGIC, WRITE_CR4, unsigned long)
#define IOCTL_SET_IN_CR4                         _IOW(IOC_MAGIC, SET_IN_CR4, unsigned long)
#define IOCTL_CLEAR_IN_CR4                       _IOW(IOC_MAGIC, CLEAR_IN_CR4, unsigned long)
#define IOCTL_SMM_TEST                           _IO(IOC_MAGIC, SMM_TEST)
#define IOCTL_INSTALL_SMI_HANDLER                _IOW(IOC_MAGIC,INSTALL_SMI_HANDLER, unsigned long)
#define IOCTL_WRITE_SMM_BYTE                     _IOW(IOC_MAGIC,WRITE_SMM_BYTE, unsigned long)
#define IOCTL_READ_SMM_BYTE                      _IOWR(IOC_MAGIC,READ_SMM_BYTE, unsigned long)
#define IOCTL_RESTORE_SMI_HANDLER                _IO(IOC_MAGIC,RESTORE_SMI_HANDLER)
#define IOCTL_SEND_SMI                           _IO(IOC_MAGIC,SEND_SMI)
#define IOCTL_IS_SMM_LOCKED                      _IOR(IOC_MAGIC,IS_SMM_LOCKED,unsigned long)
#define IOCTL_INSTALL_INTERRUPT_HANDLER          _IOWR(IOC_MAGIC,INSTALL_INTERRUPT_HANDLER,unsigned long)
#define IOCTL_REMOVE_INTERRUPT_HANDLER           _IOWR(IOC_MAGIC,REMOVE_INTERRUPT_HANDLER,unsigned long)
#define IOCTL_READ_INTERRUPT_DATA                _IOWR(IOC_MAGIC,READ_INTERRUPT_DATA,unsigned long)
#define IOCTL_WRITE_INTERRUPT_DATA               _IOWR(IOC_MAGIC,WRITE_INTERRUPT_DATA,unsigned long)
#define IOCTL_DISABLE_INTERRUPT_HANDLER          _IOWR(IOC_MAGIC,DISABLE_INTERRUPT_HANDLER,unsigned long)
#define IOCTL_ENABLE_INTERRUPT_HANDLER          _IOWR(IOC_MAGIC,ENABLE_INTERRUPT_HANDLER,unsigned long)
#define IOCTL_INTERRUPT_TEST                    _IOWR(IOC_MAGIC,INTERRUPT_TEST,unsigned long)
#define IOCTL_INVALIDATE_PAGE                    _IOW(IOC_MAGIC, INVALIDATE_PAGE, unsigned long)
#define IOCTL_INVALIDATE_TLB                     _IO(IOC_MAGIC, INVALIDATE_TLB)
#define IOCTL_INVALIDATE_CACHES                  _IO(IOC_MAGIC, INVALIDATE_CACHES)
#define IOCTL_FLUSH_CACHE_LINE                    _IOW(IOC_MAGIC, FLUSH_CACHE_LINE, unsigned long)
#define IOCTL_READ_GS_BASE                    _IOR(IOC_MAGIC, READ_GS_BASE, unsigned long)

#define IOCTL_READ_CR2                           _IOR(IOC_MAGIC, READ_CR2, unsigned long)
#define IOCTL_WRITE_CR2                          _IOW(IOC_MAGIC, WRITE_CR2, unsigned long)
#define IOCTL_READ_CR3                           _IOR(IOC_MAGIC, READ_CR3, unsigned long)
#define IOCTL_WRITE_CR3                          _IOW(IOC_MAGIC, WRITE_CR3, unsigned long)

#define IOCTL_STGI                              _IO(IOC_MAGIC, STGI)
#define IOCTL_CLGI                              _IO(IOC_MAGIC, CLGI)


#define IOCTL_READ_CR8                           _IOR(IOC_MAGIC, READ_CR8, unsigned long)
#define IOCTL_WRITE_CR8                          _IOW(IOC_MAGIC, WRITE_CR8, unsigned long)

#define IOCTL_GET_LINEAR_ADDRESS                 _IOWR(IOC_MAGIC, GET_LINEAR_ADDRESS, unsigned long)
#define IOCTL_GET_PHYSICAL_ADDRESS               _IOWR(IOC_MAGIC, GET_PHYSICAL_ADDRESS, unsigned long)

#define IOCTL_RESERVE_VECTOR                    _IOWR(IOC_MAGIC, RESERVE_VECTOR, unsigned long)
#define IOCTL_FREE_VECTOR                       _IOWR(IOC_MAGIC, FREE_VECTOR, unsigned long)
#define IOCTL_GET_LAPIC_LINBASE                 _IOWR(IOC_MAGIC, GET_LAPIC_LINBASE, unsigned long)
#define IOCTL_HARDLOCK                          _IO(IOC_MAGIC, HARDLOCK)
#define IOCTL_READ_USER_DATA                    _IOWR(IOC_MAGIC, READ_USER_DATA, unsigned long)
#define IOCTL_WRITE_USER_DATA                   _IOWR(IOC_MAGIC, WRITE_USER_DATA, unsigned long)
#define IOCTL_SEND_INT_ALL_BUT_SELF             _IOWR(IOC_MAGIC, SEND_INT_ALL_BUT_SELF, unsigned long)
#define IOCTL_SEND_INT_ALL                      _IOWR(IOC_MAGIC, SEND_INT_ALL, unsigned long)
#define IOCTL_SEND_INT_MASK                     _IOWR(IOC_MAGIC, SEND_INT_MASK, unsigned long)
#define IOCTL_EXECUTE_INVLPGB_INSTRUCTION       _IOW(IOC_MAGIC, EXECUTE_INVLPGB_INSTRUCTION, unsigned long)
#define IOCTL_EXECUTE_TLBSYNC_INSTRUCTION       _IO(IOC_MAGIC, EXECUTE_TLBSYNC_INSTRUCTION)
#define IOCTL_SET_PTE                           _IOWR(IOC_MAGIC, SET_PTE, unsigned long)
#define IOCTL_RESERVE_MSI_VECTOR                _IOWR(IOC_MAGIC, RESERVE_MSI_VECTOR, unsigned long)
#define IOCTL_FREE_MSI_VECTOR                   _IOWR(IOC_MAGIC, FREE_MSI_VECTOR, unsigned long)


enum {
	IRQ_SIM,
	APIC_IRQ_GEN,
	SWI_GEN,
};

enum PCI_IOPORT_TYPE {
	PCI_IO_PORT_BYTE_ACCESS = 1,
	PCI_IO_PORT_WORD_ACCESS = 2,
	PCI_IO_PORT_INT_ACCESS  = 4
};

enum {
	SET_PG_DIRTY            = 1 //Set page dirty
	,SET_PG_ACCESSED        = 2 //Set page accessed
	,SET_PG_PRESENT         = 3 //Set page present
	,CLEAR_PG_DIRTY         = 4 //Clear page dirty
	,CLEAR_PG_ACCESSED      = 5 //Clear page accessed
	,CLEAR_PG_PRESENT       = 6 //Clear page present
	,CLEAR_PG_RW            = 7 //Clear page rw
};

enum {
	SET_MT_WB               = 0
	,SET_MT_WC              = 1
	,SET_MT_UC_MINUS        = 2 
	,SET_MT_UC              = 3 
	,SET_MT_WT              = 4
	,SET_MT_WP              = 5
};

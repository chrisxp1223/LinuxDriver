#include <linux/kallsyms.h>

int amd_install_smi_handler(void* code, size_t bytes);
int amd_restore_smi_handler(void);
int amd_read_smm_data_byte(unsigned char* byte, unsigned long  offset);
int amd_write_smm_data_byte(unsigned char byte, unsigned long  offset);
int amd_smm_test(void);
int amd_send_smi(unsigned long count);


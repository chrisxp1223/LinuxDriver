#ifndef AMD_COMMON_INC
#define AMD_COMMON_INC

int amd_disable_smep(void);
int amd_read_smep(void);
int amd_enable_smep(void);
int amd_restore_smep(int smep);
void amd_checkpoint(unsigned int code, unsigned int subcode);
int amd_disable_sched(void); 
int amd_enable_sched(void); 
int amd_disable_current_sched(void); 
int amd_enable_current_sched(void); 
void amd_bist_check(void);
void amd_bthb_setup(void);


#endif

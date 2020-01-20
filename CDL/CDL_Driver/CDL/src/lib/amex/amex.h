int amex_disable_tlb_flush(int cpu);
int amex_enable_tlb_flush(int cpu);
extern int amex(uint64_t target, uint64_t rsi, uint64_t rdx);

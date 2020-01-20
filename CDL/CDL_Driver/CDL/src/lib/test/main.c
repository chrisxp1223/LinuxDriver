#include <asm/amd-diagnostics/test.h>

//*******************************************************************************************

void amd_diagnostics_test(void)

{ int status = 0;
  
  status |= testNXDisabled();
}

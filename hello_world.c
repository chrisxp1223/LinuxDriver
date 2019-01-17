#include <linux/init.h>
#include <linux/module.h>
MODULE_LICENSE("Daul BSD/GPL");
static int hello_world_init (void)
{
  /* code */
  printk(KERN_ALERT "Hello World\n");
  return 0;
}

static void hello_world_exit(void)
{
  /* code */
    printk(KERN_ALERT "Goodbye World\n");
}

module_init(hello_world_init);
module_exit(hello_world_exit);

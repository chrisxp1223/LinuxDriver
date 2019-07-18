#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>


#define MAJOR_NUM 0
#define MINOR_NUM 0 
#define MODULE_NAME "HelloWorld"

dev_t hello_dev_num_t;

int hello_major = MAJOR_NUM;
int hello_minor = MINOR_NUM;


struct hello_dev_t {
    struct cdev *hello_cdev;
} hello_dev;

static ssize_t drv_read(struct file *filp, char *buf, size_t count, loff_t *ppos)
{
    printk("device read\n");
    return count;
}

static ssize_t drv_write(struct file *filp, const char *buf, size_t count, loff_t *ppos)
{
    printk("device write\n");
    return count;
}

static int drv_open(struct inode *inode, struct file *filp)
{
    printk("device open\n");
    return 0;
}
static long drv_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
    printk("device ioctl\n");
    return 0;
}

static int drv_release(struct inode *inode, struct file *filp)
{
    printk("device close\n");
    return 0;
}

struct file_operations drv_fops = {
    .read = drv_read,
    .write = drv_write,
    .open = drv_open,
    .unlocked_ioctl = drv_ioctl,
    .release = drv_release,
};

static void hello_setup_cdev (struct hello_dev_t *dev, dev_t hello_dev_num_t)
{
    int err;

   dev->hello_cdev = cdev_alloc();
   cdev_init(dev->hello_cdev, &drv_fops);
   
   dev->hello_cdev->ops = &drv_fops;
   dev->hello_cdev->owner = THIS_MODULE;

   err = cdev_add(dev->hello_cdev, hello_dev_num_t, 1);
   if (err) 
    printk (KERN_ALERT "Error %d add hello",err);
}

static void hello_remove_cdev (struct hello_dev_t *dev)
{
    cdev_del(dev->hello_cdev);
}
static int __init hello_world_init (void)
{
    int rc;

    if (hello_major) {
        hello_dev_num_t = MKDEV(hello_major,hello_minor);
        rc = register_chrdev_region(hello_dev_num_t, 0, "HelloWorld");
    } else {
        rc = alloc_chrdev_region(&hello_dev_num_t, 0, 0, "HelloWorld");
        hello_major = MAJOR(hello_dev_num_t);
    }
   
    hello_setup_cdev (&hello_dev, hello_dev_num_t);

    if (rc < 0) {
        printk("<1>%s: can't get major %d\n", MODULE_NAME, MAJOR_NUM);
        return rc;
    }
  printk(KERN_ALERT "Hello World regsiter started\n");
  return 0;
}

static void __exit hello_world_exit(void)
{
    hello_remove_cdev (&hello_dev);
    printk(KERN_ALERT "Hello World removed - Goodbye World\n");
}

MODULE_LICENSE("Daul BSD/GPL");
module_init(hello_world_init);
module_exit(hello_world_exit);

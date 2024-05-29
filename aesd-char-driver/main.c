/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"


#define AESD_UNTIL(idx, buf, lim)                                   \
    for(idx = buf->out_offs; &buf->entry[idx] != lim;               \
            idx = (idx+1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("gpcm");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static size_t scan_newline(char* str, size_t len)
{
    size_t i = 0;
    for(i = 0; i < len; i++)
    {
        if(str[i] == '\n')
            return i+1;
    }
    return -1;
}

static bool swap_and_free(struct aesd_dev* dev, char* str, size_t sz)
{
    size_t totalsz = sz + dev->extra_memory.sz;
    char* tmp = kmalloc(totalsz, GFP_KERNEL);
    if(tmp == NULL) {
        return false;
    }
    memcpy(tmp, dev->extra_memory.data, dev->extra_memory.sz);
    memcpy(tmp + dev->extra_memory.sz, str, sz);
    kfree(dev->extra_memory.data);
    dev->extra_memory.data = tmp;
    dev->extra_memory.sz = totalsz;
    return true;
}

static bool aesd_writebuffer(struct aesd_dev* dev, char* str, size_t sz)
{
    if(dev->extra_memory.data != NULL) {
        return swap_and_free(dev, str, sz);
    }
    
    dev->extra_memory.data = kmalloc(sz, GFP_KERNEL);
    if(dev->extra_memory.data == NULL)
        return false;
    
    memcpy(dev->extra_memory.data, str, sz);
    dev->extra_memory.sz = sz;

    return true;
}

static bool aesd_readbuffer(struct aesd_dev* dev, char* str)
{
    if(dev->extra_memory.data == NULL)
        return false;
    
    memcpy(str, dev->extra_memory.data, dev->extra_memory.sz);
    kfree(dev->extra_memory.data);
    dev->extra_memory.data = NULL;
    dev->extra_memory.sz = 0;

    return true;
}

static size_t aesd_cmdtok(struct aesd_dev *dev, char *str, size_t len)
{
    struct aesd_buffer_entry entry;
    char* cmd = NULL;
    do {
        size_t nl = scan_newline(str, len);
        if(nl == -1)
            break;
        
        cmd = kmalloc(nl + dev->extra_memory.sz, GFP_KERNEL);
        if(cmd == NULL) {
            return -1;
        }
        entry.size = nl + dev->extra_memory.sz;
        memcpy(cmd + dev->extra_memory.sz, str, nl);
        aesd_readbuffer(dev, cmd);
        entry.buffptr = cmd;
        
        cmd = (char*)aesd_circular_buffer_add_entry(&dev->buffer, &entry);

        kfree(cmd);
        len -= nl;
        str += nl;

    } while(len > 0);

    return len;
}

static size_t aesd_readfull(struct aesd_dev *dev, char *str)
{
    size_t len = 0;
    struct aesd_circular_buffer *buf = &dev->buffer;
    uint8_t bufflen = (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED + buf->in_offs - buf->out_offs) 
                % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    if(bufflen == 0 && buf->full) {
        bufflen = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    uint8_t i = 0;
    for(i = 0; i < bufflen; i++) {
        uint8_t entry = (buf->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        memcpy(str + len, buf->entry[entry].buffptr, buf->entry[entry].size);
        len += buf->entry[entry].size;
    }
    return len;
}

static size_t aesd_readpartial(struct aesd_dev *dev, char *str, 
            struct aesd_buffer_entry *limit, size_t offs)
{
    struct aesd_circular_buffer *buf = &dev->buffer;
    size_t len = 0;
    uint8_t i = 0;
    AESD_UNTIL(i, buf, limit) {
        memcpy(str + len, buf->entry[i].buffptr, buf->entry[i].size);
        len += buf->entry[i].size;
    }
    memcpy(str + len, limit->buffptr, offs);
    len += offs;
    return len;
}

int aesd_open(struct inode *inode, struct file *filp)
{
    /* handle open */
    struct aesd_dev *dev;
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    PDEBUG("open\n");
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    /* handle release */
    PDEBUG("release\n");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    /* handle read */
    char *str = kmalloc(count, GFP_KERNEL);
    if(str == NULL) {
        retval = -ENOMEM;
        goto err;
    }
    memset(str, 0, count);

    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry = NULL;
    size_t offs = 0;
    size_t len = 0;

    if(mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, 
                count, &offs);

    if(entry == NULL) {
        len = aesd_readfull(dev, str);
    }
    else {
        len = aesd_readpartial(dev, str, entry, offs);
    }
    
    mutex_unlock(&dev->lock);
    
    if(copy_to_user(buf, str, len)) {
        retval = -EFAULT;
        goto leave;
    }

    if(*f_pos == len) {
        *f_pos = 0;
        retval = 0;
    } else {
        *f_pos = len;
        retval = len;
    }

leave:
    kfree(str);
    
err:
    PDEBUG("read: %d\n", retval);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = count;
    /* handle write */
    struct aesd_dev *dev = filp->private_data;

    char* usrstr = kmalloc(count, GFP_KERNEL);
    if(usrstr == NULL) {
        retval = -ENOMEM;
        goto out;
    }

    if(copy_from_user(usrstr, buf, count)) {
        retval = -EFAULT;
        goto fault;
    }
    
    if(mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    size_t len = aesd_cmdtok(dev, usrstr, count);
    if(len == -1) {
        return -ENOMEM;
    }

    
    if(len > 0) {
        retval = (aesd_writebuffer(dev, (usrstr + count - len), len))? count:-ENOMEM;
    }


    mutex_unlock(&dev->lock);

fault:
    kfree(usrstr);

out:
    PDEBUG("write: %d\n", retval);
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    PDEBUG("***********************************************"
    "******************************************************\n");
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /* initialize the AESD specific portion of the device */
    aesd_circular_buffer_init(&aesd_device.buffer);
    mutex_init(&aesd_device.lock);
    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /* cleanup AESD specific poritions here as necessary */
    kfree(aesd_device.extra_memory.data);

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);

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

#undef max
#undef min

#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})


#define min(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b;       \
})

#define __circular_idx(i)   (i)      \
            % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED

#define __offset_idx(i)     (i)      \
            + AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED

#define __get_bufflen(i)    __circular_idx(__offset_idx(i))

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
        if(nl == -1) {
            break;
        }
        
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

static uint8_t aesd_applyoff(struct aesd_dev *dev, size_t off, size_t* rtn_off)
{
    struct aesd_circular_buffer *buf = &dev->buffer;
    uint8_t i = 0;
    uint8_t bufflen = __get_bufflen(buf->in_offs - buf->out_offs);
    if(bufflen == 0 && buf->full) {
        bufflen = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    int pos = off;
    for(i = 0; i < bufflen; i++) {
        pos -= buf->entry[i].size;
        if(pos <= 0) {
            *rtn_off = buf->entry[i].size + pos;
            return i;
        }
    }
    return -1;
}

static size_t aesd_readfull(struct aesd_dev *dev, uint8_t entry_i, 
                size_t offs, char *str, size_t count)
{
    size_t len = 0;
    size_t readsz = 0;
    uint8_t entry = 0;
    uint8_t i = 0;
    struct aesd_circular_buffer *buf = &dev->buffer;
    uint8_t bufflen = __get_bufflen(buf->in_offs - buf->out_offs);

    if(bufflen == 0 && buf->full) {
        bufflen = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    
    for(i = entry_i; i < bufflen && count > 0; i++) {
        entry = __circular_idx(buf->out_offs + i);
        readsz = min(count, buf->entry[entry].size - offs);  
        memcpy(str + len, buf->entry[entry].buffptr + offs, readsz);
        offs = 0;
        len += readsz;
        count -= readsz;
    }

    return len;
}

static size_t aesd_filesz(struct aesd_dev *dev)
{
    struct aesd_circular_buffer *buf = &dev->buffer;
    uint8_t bufflen = __get_bufflen(buf->in_offs - buf->out_offs);
    uint8_t i = 0;
    size_t retval = 0;
    for(i = 0; i < bufflen; i++) {
        retval += buf->entry[i].size;
    }
    return retval;
}

int aesd_open(struct inode *inode, struct file *filp)
{
    /* handle open */
    struct aesd_dev *dev;
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    filp->f_pos = 0;    /* sanity check */
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
    struct aesd_dev *dev = filp->private_data;
    size_t offs = 0;
    size_t len = 0;
    uint8_t entry = 0;

    char *str = kmalloc(count, GFP_KERNEL);
    if(str == NULL) {
        retval = -ENOMEM;
        goto out;
    }
    memset(str, 0, count);

    if(mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }
    
    entry = aesd_applyoff(dev, *f_pos, &offs);
    if(entry == -1) {
        retval = -EINVAL;
        goto unlock;
    }

    len = aesd_readfull(dev, entry, offs, str, count);
    *f_pos += len;
    retval = len;

unlock:
    mutex_unlock(&dev->lock);
    
    if(copy_to_user(buf, str, len)) {
        retval = -EFAULT;
        goto free;
    }

free:
    kfree(str);
    
out:
    PDEBUG("read: %d\n", retval);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = count;
    /* handle write */
    struct aesd_dev *dev = filp->private_data;
    size_t len = 0;

    char* usrstr = kmalloc(count, GFP_KERNEL);
    if(usrstr == NULL) {
        retval = -ENOMEM;
        goto out;
    }

    if(copy_from_user(usrstr, buf, count)) {
        retval = -EFAULT;
        goto free;
    }
    
    if(mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }
    len = aesd_cmdtok(dev, usrstr, count);
    if(len == -1) {
        retval = -ENOMEM;
        goto unlock;
    }

    if(len > 0) {
        if(aesd_writebuffer(dev, (usrstr + count - len), len)) {
            retval -=len;
        } else {
            retval = -ENOMEM;
            goto unlock;
        }
    }

    *f_pos = max(*f_pos - (loff_t)retval, 0);
    
unlock:
    mutex_unlock(&dev->lock);

free:
    kfree(usrstr);

out:
    PDEBUG("write: %d\n", retval);
    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    struct aesd_dev *dev = filp->private_data;
    size_t maxsize = 0;
    loff_t newpos = 0;
    loff_t retval = 0;

    if(mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    maxsize = aesd_filesz(dev);

    switch (whence) {
    case 0:     /* SEEK_SET */
        newpos = off;
        break;
    case 1:     /* SEEK_CURR */
        newpos = filp->f_pos + off;
        break;
    case 2:     /* SEEK_END */
        newpos = maxsize + off;
        break;
    default:
        retval = -EINVAL;
        goto unlock;
    }

    if(newpos > maxsize) {
        retval = -EINVAL;
        goto unlock;
    }

    filp->f_pos = newpos;
    retval = filp->f_pos;

unlock:
    mutex_unlock(&dev->lock);
    return retval;
}


struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
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
    dev_t dev = 0;
    int result;

    PDEBUG("***********************************************"
    "******************************************************\n");
    
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

    uint8_t index;
    struct aesd_buffer_entry *entry;

    cdev_del(&aesd_device.cdev);

    /* cleanup AESD specific poritions here as necessary */
    kfree(aesd_device.extra_memory.data);

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
        kfree(entry->buffptr);
    }

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);

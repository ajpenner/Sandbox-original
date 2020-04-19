// SPDX-License-Identifier: Closed
/*****************************************************************************
 *                           QMM Kernel Driver                               *
 *                            Version 1.00                                   *
 *             (C) 2005 Georges Toth <g.toth@e-biz.lu>                       *
 *                                                                           *
 *     This file is licensed under the GPL. See COPYING in the package.      *
 * Based on usb-skeleton.c 2.0 by Greg Kroah-Hartman (greg@kroah.com)        *
 *                                                                           *
 *                                                                           *
 * 28.02.05 Complete rewrite of the original usblcd.c driver,                *
 *          based on usb_skeleton.c.                                         *
 *          This new driver allows more than one USB-LCD to be connected     *
 *          and controlled, at once                                          *
 *****************************************************************************/
#include <linux/module.h>
//#include <linux/kernel.h>
//#include <linux/slab.h>
//#include <linux/errno.h>
//#include <linux/mutex.h>
//#include <linux/rwsem.h>
//#include <linux/uaccess.h>
#include <linux/usb.h>

#define DRIVER_VERSION "QMMUSB Driver Version 1.00"

#define USBQMM_MINOR		199

#define IOCTL_GET_HARD_VERSION	1
#define IOCTL_GET_DRV_VERSION	2

/*
static DEFINE_MUTEX(lcd_mutex);
*/
static const struct usb_device_id id_table[] = {
	{ 
        .idVendor = 0x1fc9, // Note: This is the vendor ID for the QMM module 
        .match_flags = USB_DEVICE_ID_MATCH_VENDOR, 
    },
    {
    }
};
MODULE_DEVICE_TABLE(usb, id_table);
/*
static DEFINE_MUTEX(open_disc_mutex);


struct usb_lcd {
	struct usb_device	*udev;			// init: probe_lcd
	struct usb_interface	*interface;		// the interface for this device 
	unsigned char		*bulk_in_buffer;	// the buffer to receive data
	size_t			bulk_in_size;		// the size of the receive buffer
	__u8			bulk_in_endpointAddr;	// the address of the bulk in endpoint 
	__u8			bulk_out_endpointAddr;	// the address of the bulk out endpoint
	struct kref		kref;
	struct semaphore	limit_sem;		// to stop writes at full throttle from using up all RAM 
	struct usb_anchor	submitted;		// URBs to wait for before suspend
	struct rw_semaphore	io_rwsem;
	unsigned long		disconnected:1;
};
#define to_lcd_dev(d) container_of(d, struct usb_lcd, kref)

#define USB_LCD_CONCURRENT_WRITES	5

static struct usb_driver lcd_driver;


static void lcd_delete(struct kref *kref)
{
	struct usb_lcd *dev = to_lcd_dev(kref);

	usb_put_dev(dev->udev);
	kfree(dev->bulk_in_buffer);
	kfree(dev);
}

static int lcd_open(struct inode *inode, struct file *file)
{
	struct usb_lcd *dev;
	struct usb_interface *interface;
	int subminor, r;

	mutex_lock(&lcd_mutex);
	subminor = iminor(inode);

	interface = usb_find_interface(&lcd_driver, subminor);
	if (!interface) {
		mutex_unlock(&lcd_mutex);
		printk(KERN_ERR "USBLCD: %s - error, can't find device for minor %d\n",
		       __func__, subminor);
		return -ENODEV;
	}

	mutex_lock(&open_disc_mutex);
	dev = usb_get_intfdata(interface);
	if (!dev) {
		mutex_unlock(&open_disc_mutex);
		mutex_unlock(&lcd_mutex);
		return -ENODEV;
	}

	// increment our usage count for the device
	kref_get(&dev->kref);
	mutex_unlock(&open_disc_mutex);

	// grab a power reference
	r = usb_autopm_get_interface(interface);
	if (r < 0) {
		kref_put(&dev->kref, lcd_delete);
		mutex_unlock(&lcd_mutex);
		return r;
	}

	// save our object in the file's private structure
	file->private_data = dev;
	mutex_unlock(&lcd_mutex);

	return 0;
}

static int lcd_release(struct inode *inode, struct file *file)
{
	struct usb_lcd *dev;

	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	// decrement the count on our device
	usb_autopm_put_interface(dev->interface);
	kref_put(&dev->kref, lcd_delete);
	return 0;
}

static ssize_t lcd_read(struct file *file, char __user * buffer,
			size_t count, loff_t *ppos)
{
	struct usb_lcd *dev;
	int retval = 0;
	int bytes_read;

	dev = file->private_data;

	down_read(&dev->io_rwsem);

	if (dev->disconnected) {
		retval = -ENODEV;
		goto out_up_io;
	}

	// do a blocking bulk read to get data from the device
	retval = usb_bulk_msg(dev->udev,
			      usb_rcvbulkpipe(dev->udev,
					      dev->bulk_in_endpointAddr),
			      dev->bulk_in_buffer,
			      min(dev->bulk_in_size, count),
			      &bytes_read, 10000);

	// if the read was successful, copy the data to userspace
	if (!retval) {
		if (copy_to_user(buffer, dev->bulk_in_buffer, bytes_read))
			retval = -EFAULT;
		else
			retval = bytes_read;
	}

out_up_io:
	up_read(&dev->io_rwsem);

	return retval;
}

static long lcd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct usb_lcd *dev;
	u16 bcdDevice;
	char buf[30];

	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	switch (cmd) {
	case IOCTL_GET_HARD_VERSION:
		mutex_lock(&lcd_mutex);
		bcdDevice = le16_to_cpu((dev->udev)->descriptor.bcdDevice);
		sprintf(buf, "%1d%1d.%1d%1d",
			(bcdDevice & 0xF000)>>12,
			(bcdDevice & 0xF00)>>8,
			(bcdDevice & 0xF0)>>4,
			(bcdDevice & 0xF));
		mutex_unlock(&lcd_mutex);
		if (copy_to_user((void __user *)arg, buf, strlen(buf)) != 0)
			return -EFAULT;
		break;
	case IOCTL_GET_DRV_VERSION:
		sprintf(buf, DRIVER_VERSION);
		if (copy_to_user((void __user *)arg, buf, strlen(buf)) != 0)
			return -EFAULT;
		break;
	default:
		return -ENOTTY;
		break;
	}

	return 0;
}

static void lcd_write_bulk_callback(struct urb *urb)
{
	struct usb_lcd *dev;
	int status = urb->status;

	dev = urb->context;

	// sync/async unlink faults aren't errors
	if (status &&
	    !(status == -ENOENT ||
	      status == -ECONNRESET ||
	      status == -ESHUTDOWN)) {
		dev_dbg(&dev->interface->dev,
			"nonzero write bulk status received: %d\n", status);
	}

	// free up our allocated buffer
	usb_free_coherent(urb->dev, urb->transfer_buffer_length,
			  urb->transfer_buffer, urb->transfer_dma);
	up(&dev->limit_sem);
}

static ssize_t lcd_write(struct file *file, const char __user * user_buffer,
			 size_t count, loff_t *ppos)
{
	struct usb_lcd *dev;
	int retval = 0, r;
	struct urb *urb = NULL;
	char *buf = NULL;

	dev = file->private_data;

	// verify that we actually have some data to write
	if (count == 0)
		goto exit;

	r = down_interruptible(&dev->limit_sem);
	if (r < 0)
		return -EINTR;

	down_read(&dev->io_rwsem);

	if (dev->disconnected) {
		retval = -ENODEV;
		goto err_up_io;
	}

	// create a urb, and a buffer for it, and copy the data to the urb
	urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!urb) {
		retval = -ENOMEM;
		goto err_up_io;
	}

	buf = usb_alloc_coherent(dev->udev, count, GFP_KERNEL,
				 &urb->transfer_dma);
	if (!buf) {
		retval = -ENOMEM;
		goto error;
	}

	if (copy_from_user(buf, user_buffer, count)) {
		retval = -EFAULT;
		goto error;
	}

	// initialize the urb properly
	usb_fill_bulk_urb(urb, dev->udev,
			  usb_sndbulkpipe(dev->udev,
			  dev->bulk_out_endpointAddr),
			  buf, count, lcd_write_bulk_callback, dev);
	urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

	usb_anchor_urb(urb, &dev->submitted);

	// send the data out the bulk port
	retval = usb_submit_urb(urb, GFP_KERNEL);
	if (retval) {
		dev_err(&dev->udev->dev,
			"%s - failed submitting write urb, error %d\n",
			__func__, retval);
		goto error_unanchor;
	}

	// release our reference to this urb,
	// the USB core will eventually free it entirely
	usb_free_urb(urb);

	up_read(&dev->io_rwsem);
exit:
	return count;
error_unanchor:
	usb_unanchor_urb(urb);
error:
	usb_free_coherent(dev->udev, count, buf, urb->transfer_dma);
	usb_free_urb(urb);
err_up_io:
	up_read(&dev->io_rwsem);
	up(&dev->limit_sem);
	return retval;
}

static const struct file_operations qmm_fops = {
	.owner =        THIS_MODULE,
	.read =         lcd_read,
	.write =        lcd_write,
	.open =         lcd_open,
	.unlocked_ioctl = lcd_ioctl,
	.release =      lcd_release,
	.llseek =	 noop_llseek,
};
*/
/*
 * usb class driver info in order to get a minor number from the usb core,
 * and to have the device registered with the driver core
 */
/*
static struct usb_class_driver qmm_class = {
	.name =         "qmm%d",
	.fops =         &qmm_fops,
	.minor_base =   USBQMM_MINOR,
};
*/
static int qmm_probe(struct usb_interface *interface,
		     const struct usb_device_id *id)
{
    printk(KERN_DEBUG "QMMUSB: I am probed");
    return 0;
}

static int qmm_suspend(struct usb_interface *intf, pm_message_t message)
{
    printk(KERN_DEBUG "QMMUSB: I am suspended");
	return 0;
}

static int qmm_resume(struct usb_interface *intf)
{
    printk(KERN_DEBUG "QMMUSB: I am resuming");
	return 0;
}

static void qmm_disconnect(struct usb_interface *interface)
{
    printk(KERN_DEBUG "QMMUSB: I am disconnected");
    return;
}

static struct usb_driver qmm_driver = {
	.name =		    "usbqmm",
	.probe =	    qmm_probe,
	.disconnect =   qmm_disconnect,
	.suspend =  	qmm_suspend,
	.resume =	    qmm_resume,
	.id_table =	    id_table,
	.supports_autosuspend = 1,
};

module_usb_driver(qmm_driver);

MODULE_AUTHOR("Andrew Penner <Andrew.Penner@Domino-UK.com>");
MODULE_DESCRIPTION(DRIVER_VERSION);
MODULE_LICENSE("GPL");

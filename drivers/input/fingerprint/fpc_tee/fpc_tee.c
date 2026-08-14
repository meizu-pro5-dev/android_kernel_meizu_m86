/*
 * Meizu m86 FPC secure-world IRQ and resource bridge.
 *
 * The production FPC HAL does not transfer sensor frames through Linux.
 * It talks to the 0401 Trustonic TA and uses these SPI-device sysfs files
 * solely for IRQ notification, wakeup, SPI clocks and secure-OS boosting.
 */

#include <linux/atomic.h>
#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/platform_data/spi-s3c64xx.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
#include <linux/wakelock.h>

#ifdef CONFIG_SECURE_OS_BOOSTER_API
#include <linux/soc/samsung/secos_booster.h>
#endif

#define FPC_TTW_HOLD_TIME_MS 1000

struct fpc_tee_data {
	struct spi_device *spi;
	struct mutex lock;
	struct wake_lock ttw_wake_lock;
	struct completion irq_sent;
	struct regulator *vdd28_fp;
	atomic_t wakeup_enabled;
	int irq_gpio;
	int reset_gpio;
	bool clocks_enabled;
	bool boost_locked;
};

static int fpc_tee_named_gpio(struct device_node *node, const char *primary,
			      const char *fallback)
{
	int gpio;

	gpio = of_get_named_gpio(node, primary, 0);
	if (!gpio_is_valid(gpio) && fallback)
		gpio = of_get_named_gpio(node, fallback, 0);

	return gpio;
}

static int fpc_tee_set_clocks(struct fpc_tee_data *fpc, bool enable)
{
	struct s3c64xx_spi_driver_data *sdd;
	int ret = 0;

	sdd = spi_master_get_devdata(fpc->spi->master);
	if (!sdd || !sdd->pdev)
		return -ENODEV;

	mutex_lock(&fpc->lock);
	if (enable == fpc->clocks_enabled)
		goto out;

	if (enable) {
		ret = pm_runtime_get_sync(&sdd->pdev->dev);
		if (ret < 0) {
			pm_runtime_put_noidle(&sdd->pdev->dev);
			goto out;
		}
		/*
		 * The FPC1020 sensor runs its SPI at 4.8 MHz: the raw fpc1020
		 * driver uses chip.spi_max_khz = 4800 and the sensor answers
		 * reliably at that rate.  The DTS entry (16 MHz) is only the
		 * controller upper bound; driving the sensor at that rate makes
		 * the FPC trustlet report FPC_ERROR_RESET_HARDWARE.  Set the
		 * source to twice the sensor clock so the controller divider
		 * produces exactly 4.8 MHz.
		 */
		ret = clk_set_rate(sdd->src_clk, 4800000u * 2);
		if (ret) {
			pm_runtime_put(&sdd->pdev->dev);
			goto out;
		}
		fpc->clocks_enabled = true;
		ret = 0;
	} else {
		pm_runtime_put(&sdd->pdev->dev);
		fpc->clocks_enabled = false;
	}

out:
	mutex_unlock(&fpc->lock);
	return ret;
}

static ssize_t irq_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct fpc_tee_data *fpc = dev_get_drvdata(dev);
	ssize_t count;

	count = scnprintf(buf, PAGE_SIZE, "%d\n",
			  gpio_get_value(fpc->irq_gpio));

	/*
	 * Production FPC IRQ protocol: the threaded handler holds the ONESHOT
	 * IRQ masked until userland has consumed the notification, so ack it
	 * on read exactly like the stock fpc_irq driver does.
	 */
	complete(&fpc->irq_sent);

	return count;
}

/*
 * The FPC HAL opens this node read-write; its write is only an IRQ ack for
 * latency measurement in the production fpc_irq driver, so consume the write
 * and report success.
 */
static ssize_t irq_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	dev_dbg(dev, "%s\n", __func__);
	return count;
}

static ssize_t wakeup_enable_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct fpc_tee_data *fpc = dev_get_drvdata(dev);
	bool enable;

	if (sysfs_streq(buf, "enable"))
		enable = true;
	else if (sysfs_streq(buf, "disable"))
		enable = false;
	else
		return -EINVAL;

	if (enable == !!atomic_read(&fpc->wakeup_enabled))
		return count;

	if (enable) {
		enable_irq_wake(fpc->spi->irq);
		atomic_set(&fpc->wakeup_enabled, 1);
	} else {
		atomic_set(&fpc->wakeup_enabled, 0);
		disable_irq_wake(fpc->spi->irq);
	}

	return count;
}

static ssize_t clk_enable_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct fpc_tee_data *fpc = dev_get_drvdata(dev);
	bool enable;
	int ret;

	/*
	 * Flyme 8's lib_fpc_tac_shared keeps a two-byte command buffer and
	 * writes "11" while enabling and "01" while disabling the SPI clock.
	 * The production fpc_irq driver consumes the first byte.  Accept that
	 * ABI as well as the conventional one-byte sysfs form.
	 */
	if (count && buf[0] == '1')
		enable = true;
	else if (count && buf[0] == '0')
		enable = false;
	else
		return -EINVAL;

	ret = fpc_tee_set_clocks(fpc, enable);
	return ret ? ret : count;
}

static ssize_t lock_freq_store(struct device *dev,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct fpc_tee_data *fpc = dev_get_drvdata(dev);
	bool lock;
	int ret = 0;

	if (sysfs_streq(buf, "lock"))
		lock = true;
	else if (sysfs_streq(buf, "unlock"))
		lock = false;
	else
		return -EINVAL;

	mutex_lock(&fpc->lock);
	if (lock != fpc->boost_locked) {
#ifdef CONFIG_SECURE_OS_BOOSTER_API
		ret = lock ? secos_booster_start(MAX_PERFORMANCE) :
			secos_booster_stop();
#endif
		if (!ret)
			fpc->boost_locked = lock;
	}
	mutex_unlock(&fpc->lock);

	return ret ? ret : count;
}

static ssize_t hw_reset_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct fpc_tee_data *fpc = dev_get_drvdata(dev);

	if (!gpio_is_valid(fpc->reset_gpio))
		return -ENODEV;

	gpio_set_value(fpc->reset_gpio, 1);
	usleep_range(100, 200);
	gpio_set_value(fpc->reset_gpio, 0);
	usleep_range(1000, 1500);
	gpio_set_value(fpc->reset_gpio, 1);
	usleep_range(1200, 1700);

	return count;
}

static DEVICE_ATTR(irq, S_IRUGO | S_IWUSR | S_IWGRP, irq_show, irq_store);
static DEVICE_ATTR(wakeup_enable, S_IWUSR | S_IWGRP, NULL,
		   wakeup_enable_store);
static DEVICE_ATTR(clk_enable, S_IWUSR | S_IWGRP, NULL, clk_enable_store);
static DEVICE_ATTR(lock_freq, S_IWUSR | S_IWGRP, NULL, lock_freq_store);
static DEVICE_ATTR(hw_reset, S_IWUSR | S_IWGRP, NULL, hw_reset_store);

static struct attribute *fpc_tee_attrs[] = {
	&dev_attr_irq.attr,
	&dev_attr_wakeup_enable.attr,
	&dev_attr_clk_enable.attr,
	&dev_attr_lock_freq.attr,
	&dev_attr_hw_reset.attr,
	NULL,
};

static const struct attribute_group fpc_tee_attr_group = {
	.attrs = fpc_tee_attrs,
};

static irqreturn_t fpc_tee_irq_handler(int irq, void *handle)
{
	struct fpc_tee_data *fpc = handle;

	if (atomic_read(&fpc->wakeup_enabled))
		wake_lock_timeout(&fpc->ttw_wake_lock,
				  msecs_to_jiffies(FPC_TTW_HOLD_TIME_MS));

	sysfs_notify(&fpc->spi->dev.kobj, NULL, dev_attr_irq.attr.name);

	/*
	 * Keep the ONESHOT IRQ masked until the HAL reads the irq node, which
	 * acks through irq_show().  The stock fpc_irq driver does the same
	 * with a 100 ms cap so a dead HAL cannot wedge the sensor IRQ line.
	 */
	INIT_COMPLETION(fpc->irq_sent);
	wait_for_completion_timeout(&fpc->irq_sent, msecs_to_jiffies(100));

	return IRQ_HANDLED;
}

static int fpc_tee_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct fpc_tee_data *fpc;
	int ret;

	fpc = devm_kzalloc(dev, sizeof(*fpc), GFP_KERNEL);
	if (!fpc)
		return -ENOMEM;

	fpc->spi = spi;
	fpc->irq_gpio = fpc_tee_named_gpio(dev->of_node, "gx,gpio_irq",
					   "fpc,gpio_irq");
	fpc->reset_gpio = fpc_tee_named_gpio(dev->of_node, "gx,gpio_reset",
					     "fpc,gpio_reset");
	if (!gpio_is_valid(fpc->irq_gpio))
		return -EINVAL;

	ret = devm_gpio_request(dev, fpc->irq_gpio, "fpc_irq");
	if (ret)
		return ret;
	ret = gpio_direction_input(fpc->irq_gpio);
	if (ret)
		return ret;

	if (gpio_is_valid(fpc->reset_gpio)) {
		ret = devm_gpio_request(dev, fpc->reset_gpio, "fpc_reset");
		if (ret)
			return ret;
		ret = gpio_direction_output(fpc->reset_gpio, 1);
		if (ret)
			return ret;
	}

	/*
	 * Power the sensor's 2.8 V rail (L22).  The production FPC TEE
	 * drivers manage their regulators (vcc_spi/vdd) and the m86 raw
	 * fpc1020 driver enables the same vdd28_fp L22 at probe; without it
	 * the FPC1020 only works if the boot defaults happen to leave the
	 * rail on.  Treat a missing regulator as non-fatal: some DTS variants
	 * may not expose it under this name.
	 */
	fpc->vdd28_fp = regulator_get(dev, "vdd28_fp");
	if (IS_ERR(fpc->vdd28_fp)) {
		dev_info(dev, "no vdd28_fp regulator (%ld); relying on boot state\n",
			 PTR_ERR(fpc->vdd28_fp));
		fpc->vdd28_fp = NULL;
	} else if (regulator_enable(fpc->vdd28_fp)) {
		dev_warn(dev, "failed to enable vdd28_fp\n");
		regulator_put(fpc->vdd28_fp);
		fpc->vdd28_fp = NULL;
	} else {
		dev_info(dev, "enabled vdd28_fp sensor supply\n");
	}

	spi->irq = gpio_to_irq(fpc->irq_gpio);
	if (spi->irq < 0)
		return spi->irq;

	mutex_init(&fpc->lock);
	init_completion(&fpc->irq_sent);
	atomic_set(&fpc->wakeup_enabled, 0);
	wake_lock_init(&fpc->ttw_wake_lock, WAKE_LOCK_SUSPEND, "fpc_ttw_wl");
	spi_set_drvdata(spi, fpc);

	ret = devm_request_threaded_irq(dev, spi->irq, NULL,
					fpc_tee_irq_handler,
					IRQF_TRIGGER_RISING | IRQF_ONESHOT,
					"fpc_irq", fpc);
	if (ret)
		goto err_wake_lock;

	ret = sysfs_create_group(&dev->kobj, &fpc_tee_attr_group);
	if (ret)
		goto err_wake_lock;

	dev_info(dev, "secure FPC IRQ bridge ready\n");
	return 0;

err_wake_lock:
	wake_lock_destroy(&fpc->ttw_wake_lock);
	return ret;
}

static int fpc_tee_remove(struct spi_device *spi)
{
	struct fpc_tee_data *fpc = spi_get_drvdata(spi);

	sysfs_remove_group(&spi->dev.kobj, &fpc_tee_attr_group);
	if (atomic_read(&fpc->wakeup_enabled))
		disable_irq_wake(spi->irq);
	if (fpc->clocks_enabled)
		fpc_tee_set_clocks(fpc, false);
	if (fpc->vdd28_fp) {
		regulator_disable(fpc->vdd28_fp);
		regulator_put(fpc->vdd28_fp);
	}
#ifdef CONFIG_SECURE_OS_BOOSTER_API
	if (fpc->boost_locked)
		secos_booster_stop();
#endif
	wake_lock_destroy(&fpc->ttw_wake_lock);
	return 0;
}

static const struct of_device_id fpc_tee_of_match[] = {
	{ .compatible = "fpc,fpc_irq" },
	{}
};
MODULE_DEVICE_TABLE(of, fpc_tee_of_match);

static const struct spi_device_id fpc_tee_id[] = {
	{ "fpc_irq", 0 },
	{}
};
MODULE_DEVICE_TABLE(spi, fpc_tee_id);

static struct spi_driver fpc_tee_driver = {
	.driver = {
		.name = "fpc_irq",
		.owner = THIS_MODULE,
		.of_match_table = fpc_tee_of_match,
	},
	.probe = fpc_tee_probe,
	.remove = fpc_tee_remove,
	.id_table = fpc_tee_id,
};

module_spi_driver(fpc_tee_driver);

MODULE_AUTHOR("LineageOS m86 maintainers");
MODULE_DESCRIPTION("Meizu m86 FPC Trustonic IRQ bridge");
MODULE_LICENSE("GPL v2");

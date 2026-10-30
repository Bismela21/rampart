# contrib

Optional modules that are not part of the core install:

* **proxmox/** (planned): host-level collection for Proxmox VE (integrity of guests, backups, auto-isolation of a compromised guest, restore tests), the part of the original RMON that is specific to a hypervisor.
* **wordpress-sentinel/** (planned): a must-use plugin that reports file changes, new administrators and hidden links to RMON for sites you do not host yourself.
* **android/** (planned): the Android app (alerts, status, unblock) built with your own signing key and your own Firebase project, or with ntfy for push and no Google at all.

The core (`rmon/`) never depends on these.

# USB4 / Thunderbolt 3

This implements a basic kernel driver and userland tool for USB4 and
Thunderbolt3.  The relevant code is in the following locations:

 - sys/dev/thunderbolt
 - sys/modules/thunderbolt
 - usr.sbin/tbtconfig

This code has been developed against Alpine Ridge and Icelake Thunderbolt3
controllers.  Other controllers could be supported, but additions will be
required.  Also, a full Host Connection Manager does not yet exist, only
the building blocks, so full USB4 functionality does not work yet.

Besides implementing a driver for the NHI control device, this stack also
overrides the PCIB drivers that belong to Thunderbolt/USB4 switches
(upstream and downstream ports) so that protocol-specific configuration can
be peformed without having to hack existing PCIe drivers or cross scope
boundaries in the drivers.

The Thunderbolt security model is minimally supported.  If User Authentication
is specified in the BIOS, then the driver will automatically authenticate
any device that is presented.  There's a sysctl to turn this off.  True
user-interactive authentication is not implemented, but could be with minimal
effort.  Pre-shared key authentication is also not supported.

DMAR intergration is needed in order to have a useful security/protection
model.  Also, DPC is needed, as well as plenty of work on the PCIe attach /
detach routines of FreeBSD and many of its drivers.


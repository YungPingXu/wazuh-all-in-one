# Run this script as root.
echo '#!/bin/bash' > '/etc/rc.local'
echo -e "\n\nexit 0" >> '/etc/rc.local'
chmod a+x /etc/rc.local
echo -e "[Unit]\n Description=/etc/rc.local Compatibility\n ConditionPathExists=/etc/rc.local\n\n[Service]\n
Type=forking\n ExecStart=/etc/rc.local start\n TimeoutSec=0\n StandardOutput=tty\n RemainAfterExit=yes\n
SysVStartPriority=99\n\n[Install]\n WantedBy=multi-user.target\n" > '/etc/systemd/system/rc-local.service'
systemctl enable rc-local
systemctl start rc-local
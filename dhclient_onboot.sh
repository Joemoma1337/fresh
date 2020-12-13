#!/bin/bash
echo 'Enter Interface'
read int
echo '#!/bin/bash' > /etc/rc.local
echo 'dhclient -v $int' >> /etc/rc.local
echo 'exit 0' >> /etc/rc.local

chmod 755 /etc/rc.local
systemctl enable rc-local
systemctl restart rc-local
echo 'complete'

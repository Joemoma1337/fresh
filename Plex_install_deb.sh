#!/bin/bash
apt -y update
apt -y upgrade
wget https://downloads.plex.tv/plex-media-server-new/1.22.1.4228-724c56e62/debian/plexmediaserver_1.22.1.4228-724c56e62_amd64.deb -O /tmp/plexmediaserver_1.22.1.4228-724c56e62_amd64.deb
dpkg -i /tmp/plexmediaserver*
systemctl status plexmediaserver
if [ -e /etc/apt/sources.list.d/plex* ]
then
	echo "file exists"
else
	echo deb https://downloads.plex.tv/repo/deb public main | sudo tee /etc/apt/sources.list.d/plexmediaserver.list
fi

#sudo ufw allow 32400
#
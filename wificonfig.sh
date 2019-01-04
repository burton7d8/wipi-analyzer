#!/bin/bash
if [ "$(whoami)" != "root" ]
	then
		echo "You must use sudo! ie: sudo ./wificonfig.sh"
		exit 1
	fi
	read -p "Do you wish to update the WIFI settings? ( y/n ) : " -t 5 yn
	case $yn in
	[Yy]* ) 
		read -p "ENTER NEW SSID (enter blank to disable): " ssid
		if [ -z "$ssid" ]
		then
			echo Turning off Wifi
			wpa_cli -i wlan0 remove_network 0
			wpa_cli -i wlan0 save
			wpa_cli -i wlan0 reconfigure
			exit 1
		else
			echo You entered $ssid;
			read -p "ENTER NEW PASSWORD FOR $ssid :" wifipw
			echo You entered password: $wifipw
			echo Now updating wifi settings to be ssid: $ssid password: $wifipw 

			wpa_cli -i wlan0 remove_network 0
			wpa_cli -i wlan0 save
			wpa_passphrase $ssid $wifipw >> /etc/wpa_supplicant/wpa_supplicant.conf
			wpa_cli -i wlan0 reconfigure
		fi	
	;;
    	[Nn]* ) 
	exit 1
	;;
 * ) echo "No input detected..Not changing WIFI INFO";;
esac

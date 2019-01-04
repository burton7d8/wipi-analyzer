<?php
$shared_key = "wipi";
$skip_ssl_checking = "yes";
$wipi_server_url = "https://172.20.0.103/wipi/wipi-analyzer-server/wipi.php";


error_reporting(E_ALL ^ E_NOTICE);

$da_date = date("m-d-Y H:i");
$pi_hostname = gethostname();


$gateway = trim(preg_replace('!\s+!',';',`netstat -r | grep default`));;
$gateway = explode(";",$gateway);
$gateway = $gateway[1];

$ip_addr = `ip addr show | grep 'inet ' | grep -v 127 | awk '{print $2}'`;
$myip = strtok($ip_addr,"/");
$oc1 = strtok($ip_addr,".");
$oc2 = strtok(".");
$oc3 = strtok(".");
$oc4 = strtok("/");
$slash = strtok("\n");
$nmap_range = $oc1.".".$oc2.".".$oc3.".0"."/$slash";
$nmap = `sudo nmap --dns-servers $gateway -snP $nmap_range | grep 'report\|MAC' | grep -v $myip`;
//print "$nmap";
$stop = "no";
$counter = 0;
if(strtok($nmap,"m"))
{
	while($stop != "yes")
	{
		$counter++;
		if($counter > 500)
			$stop = "yes";

		$tok = strtok("r");
		$tok = strtok("r");
		$tok = strtok("r");
		$hostname_ip = strtok("\n");
		//$hostname = trim(strtok("("));
		//$ip = strtok(")");
		$tok = strtok(":");
		$mac = trim(strtok("("));
		$mfc = strtok(")");

		if(strtok("N"))
		{
			$stop = "no";
			$dirty_devices[] = "$hostname_ip;$mac;$mfc";
		}
		else
		{
			$stop = "yes";
		}

		//print "counter:$counter";
		//print_r($devices);

	}
}
//print_r($dirty_devices);
foreach($dirty_devices as $key => $dadevices)
{
	$hostname_ip = strtok($dadevices,";");
	$mac = strtok(";");
	$mfc = strtok("\n");
	
	if(preg_match("/\(/i",$hostname_ip))
	{
		$hostname = trim(strtok($hostname_ip,"("));
		$ip = strtok(")");
	}
	else
	{
		$hostname = "";
		$ip = trim(strtok($hostname_ip,"\n"));
	}
	$devices[] = "$hostname;$ip;$mac;$mfc";
}
//print_r($devices);

$wifi_stats = `iwconfig wlan0`;
//print $wifi_stats;
$tok = strtok($wifi_stats,":");
$ssid = strtok("\n");
$ssid = preg_replace("/\s+/"," ",$ssid);
$ssid = str_replace("\"","",$ssid);
$tok = strtok(":");
$tok = strtok(":");
//$freq = strtok(" "); //couldnt' use this one, come to find out it doesnt update properly
$tok = strtok(":");
$ap = trim(strtok("\n"));
$tok = strtok("=");
$bitrate = strtok(" ");
$tok = strtok("=");
$txpwr = strtok(" ");
$tok = strtok("=");
$quality1 = strtok("/");
$quality2 = strtok(" ");
$quality_percent = round(($quality1 / $quality2) * 100);
$tok = strtok("=");
$sig_level = strtok(" ");
$tok = strtok(":");
$rx_invalid_nwid = strtok(" ");
$tok = strtok(":");
$rx_invalid_crypt = strtok(" ");
$tok = strtok(":");
$rx_invalid_frag = strtok("\n");
$tok = strtok(":");
$tx_excessive_retries = strtok(" ");
$tok = strtok(":");
$invalid_misc = strtok(" ");
$tok = strtok(":");
$missed_beacon = strtok("\n");


$wifi_channel_info = `sudo iw dev wlan0 info`;
$tok = strtok($wifi_channel_info,":");
$tok = strtok(":");
$tok = strtok(":");
$tok = strtok(":");
$tok = strtok(":");
$tok = strtok("(");
$freq = trim(strtok("M"));
$tok = strtok(":");
$width = trim(strtok("M"));
$tok = strtok(":");
$center_freq = strtok(" ");
//print "width: $width freq:$freq center_freq:$center_freq\n";

/*
$scan = `wpa_cli -i wlan0 scan`;
sleep(2);
$scan_results = `wpa_cli -i wlan0 scan_results`;
$scan_results = explode("\n",$scan_results);
array_pop($scan_results);
*/
$scan_results = `sudo iw wlan0 scan`;
$scan_results = explode("\n",$scan_results);
//print_r($scan_results);
$ssid_counter=0;
foreach($scan_results as $key => $value)
{
	if(preg_match("/\(on wlan/i",$value))
	{
		$ssid_counter++;
		$tok = strtok($value," ");
		if(!preg_match("/ATIM window:/i",$value))
			$ssid_scan_results[$ssid_counter]["ap"] = trim(strtok("("));
		else
		{
			$tok = strtok(":");
			$tok = strtok("S");
			$tok = strtok(" ");
			$ssid_scan_results[$ssid_counter]["ap"] = trim(strtok("("));
		}
	}
	
	if(preg_match("/freq: /i",$value))
	{
		$tok = strtok($value,":");
		$ssid_scan_results[$ssid_counter]["start_freq"] = trim(strtok("\n"));
	}
	elseif(preg_match("/last seen: /i",$value))
	{
		$tok = strtok($value,":");
		$ssid_scan_results[$ssid_counter]["last_seen"] = trim(strtok(" "));
	}
	elseif(preg_match("/station count:/i",$value))
	{
		$tok = strtok($value,":");
		$ssid_scan_results[$ssid_counter]["station_count"] = trim(strtok("\n"));
	}
	elseif(preg_match("/channel utilisation: /i",$value))
	{
		$tok = strtok($value,":");
		$ch_utilisation = trim(strtok("/"));
		$ch_utilisation_total = trim(strtok("\n"));
		print "ch_utilsation: $ch_utilisation ch_utilisation_total: $ch_utilisation_total\n";
		$ch_utilisation_percent = round($ch_utilisation / $ch_utilisation_total, 2) * 100;
		$ssid_scan_results[$ssid_counter]["ch_utilisiation"] = $ch_utilisation_percent;
	}
	elseif(preg_match("/signal: /i",$value))
	{
		$tok = strtok($value,":");
		$ssid_scan_results[$ssid_counter]["siglevel"] = trim(strtok(" "));
	}
	elseif(preg_match("/SSID: /i",$value))
	{
		$tok = strtok($value,":");
		$ssid_scan_results[$ssid_counter]["ssid"] = trim(strtok("\n"));
	}
	elseif(preg_match("/primary channel: /i",$value))
	{
		$tok = strtok($value,":");
		$ssid_scan_results[$ssid_counter]["start_channel"] = trim(strtok("\n"));
	}
	elseif(preg_match("/\* STA channel width: /i",$value))
	{
		$tok = strtok($value,":");
		$ssid_scan_results[$ssid_counter]["sta_width"] = trim(strtok("M"));
	}
	elseif(preg_match("/\* channel width: 1/i",$value))
	{
		$tok = strtok($value,"(");
		$ssid_scan_results[$ssid_counter]["vht_width"] = trim(strtok(" "));
	}
	elseif(preg_match("/\* center freq segment 1:/i",$value))
	{
		$tok = strtok($value,":");
		$ssid_scan_results[$ssid_counter]["center_freq_channel"] = trim(strtok("\n"));
	}
	
	
}
//print_r($ssid_scan_results);


//$ssid_count = count($ssid_scan_results) - 1;
$ssid_count = count($ssid_scan_results);
//print_r($scan_results);
$cleanfreq = str_replace(".","",$freq);
$cleanwidth = str_replace(" ","",$width);
print "cleanwidth:$cleanwidth cleanfreq:$cleanfreq center_freq:$center_freq\n";

$wifi_freq_table[] = array("1","2401","2412","2423","20");
$wifi_freq_table[] = array("2","2406","2417","2428","20");
$wifi_freq_table[] = array("3","2411","2422","2433","20");
$wifi_freq_table[] = array("4","2416","2427","2438","20");
$wifi_freq_table[] = array("5","2421","2432","2443","20");
$wifi_freq_table[] = array("6","2426","2437","2448","20");
$wifi_freq_table[] = array("7","2431","2442","2453","20");
$wifi_freq_table[] = array("8","2436","2447","2458","20");
$wifi_freq_table[] = array("9","2441","2452","2463","20");
$wifi_freq_table[] = array("10","2446","2457","2468","20");
$wifi_freq_table[] = array("11","2451","2462","2473","20");


$wifi_freq_table[] = array("36","5170","5180","5190","20");
$wifi_freq_table[] = array("38","5170","5190","5210","40");
$wifi_freq_table[] = array("40","5190","5200","5210","20");
$wifi_freq_table[] = array("42","5170","5210","5250","80");
$wifi_freq_table[] = array("44","5210","5220","5230","20");
$wifi_freq_table[] = array("46","5210","5230","5250","40");
$wifi_freq_table[] = array("48","5230","5240","5250","20");
$wifi_freq_table[] = array("50","5170","5250","5330","160");
$wifi_freq_table[] = array("52","5250","5260","5270","20");
$wifi_freq_table[] = array("54","5250","5270","5290","40");
$wifi_freq_table[] = array("56","5270","5280","5290","20");
$wifi_freq_table[] = array("58","5250","5290","5330","80");
$wifi_freq_table[] = array("60","5290","5300","5310","20");
$wifi_freq_table[] = array("62","5290","5310","5330","40");
$wifi_freq_table[] = array("64","5310","5320","5330","20");
$wifi_freq_table[] = array("100","5490","5500","5510","20");
$wifi_freq_table[] = array("102","5490","5510","5530","40");
$wifi_freq_table[] = array("104","5510","5520","5530","20");
$wifi_freq_table[] = array("106","5490","5530","5570","80");
$wifi_freq_table[] = array("108","5530","5540","5550","20");
$wifi_freq_table[] = array("110","5530","5550","5570","40");
$wifi_freq_table[] = array("112","5550","5560","5570","20");
$wifi_freq_table[] = array("114","5490","5570","5650","160");
$wifi_freq_table[] = array("116","5570","5580","5590","20");
$wifi_freq_table[] = array("118","5570","5590","5610","40");
$wifi_freq_table[] = array("120","5590","5600","5610","20");
$wifi_freq_table[] = array("122","5570","5610","5650","80");
$wifi_freq_table[] = array("124","5610","5620","5630","20");
$wifi_freq_table[] = array("126","5610","5630","5650","40");
$wifi_freq_table[] = array("128","5630","5640","5650","20");
$wifi_freq_table[] = array("132","5650","5660","5670","20");
$wifi_freq_table[] = array("134","5650","5670","5690","40");
$wifi_freq_table[] = array("136","5670","5680","5690","20");
$wifi_freq_table[] = array("138","5650","5690","5730","80");
$wifi_freq_table[] = array("140","5690","5700","5710","20");
$wifi_freq_table[] = array("142","5690","5710","5730","40");
$wifi_freq_table[] = array("144","5710","5720","5730","20");
$wifi_freq_table[] = array("149","5735","5745","5755","20");
$wifi_freq_table[] = array("151","5735","5755","5775","40");
$wifi_freq_table[] = array("153","5755","5765","5775","20");
$wifi_freq_table[] = array("155","5735","5775","5815","80");
$wifi_freq_table[] = array("157","5775","5785","5795","20");
$wifi_freq_table[] = array("159","5775","5795","5815","40");
$wifi_freq_table[] = array("161","5795","5805","5815","20");
$wifi_freq_table[] = array("165","5815","5825","5835","20"); 

//print_r($wifi_freq_table);
foreach($wifi_freq_table as $key => $value)
{
	$channel = $value[0];
	$lowfreq = $value[1];
	$centerfreq = $value[2];
	$highfreq = $value[3];
	$freqwidth = $value[4];
	
	if($cleanfreq == $centerfreq)
	{
		$active_channel = $channel;
		break;
	}
}
if($cleanfreq != $center_freq)
{
	foreach($wifi_freq_table as $key => $value)
	{
		$channel = $value[0];
		$lowfreq = $value[1];
		$centerfreq = $value[2];
		$highfreq = $value[3];
		$freqwidth = $value[4];
		
		if($center_freq == $centerfreq)
		{
			$compare_channel = $channel;
			break;
		}
	}
}
//=======================================================  Now that you know the center frequency and what channel, you can check for overlapping channels in the wifi scan list below and only output interference channels
//print "active channel: $active_channel\n";
//die();
//print "SSID: $ssid FREQ: $freq AP: $ap BITRATE: $bitrate TXPWR: $txpwr QUALITY: $quality1/$quality2 QUALITY PERCENT: $quality_percent% SIGNAL LEVEL: $sig_level RX INVALID NWID: $rx_invalid_nwid RX INVALID CRYPT: $rx_invalid_crypt RX INVALID FRAG: $rx_invalid_frag TX EXCESSIVE RETRIES: $tx_excessive_retries INVALID MISC: $invalid_misc MISSED BEACON: $missed_beacon\n";

//print_r($devices);
$log = fopen("/home/pi/logs/wifi_info.log","a") or die("Unable to open file!");
$line = "====================================== $da_date  ==========================================\n\n";
fwrite($log, $line);
print $line;

$line = "\n\t\t\t\t ---=== CONNECTED WIFI INFO [$ssid] ===---\n";
fwrite($log, $line);
print $line;

$line = "\tSSID: $ssid AP: $ap FREQ: $cleanfreq CHANNEL: $active_channel WIDTH: $width LINK QUALITY %: $quality_percent% SIGNAL LEVEL: $sig_level BIT RATE: $bitrate\n";
fwrite($log, $line);
print $line;
$line = "\tTXPWR: $txpwr LINK QUALITY: $quality1/$quality2 rx_invalid_nwid: $rx_invalid_nwid rx_invalid_crypt: $rx_invalid_crypt rx_invalid_frag: $rx_invalid_frag\n";
fwrite($log, $line);
print $line;
$line = "\ttx_excessive_retries: $tx_excessive_retries invalid_misc: $invalid_misc missed_beacon: $missed_beacon\n\n";
fwrite($log, $line);
print $line;

$wifi_stats="$ssid;$ap;$cleanfreq;$quality1/$quality2;$quality_percent;$sig_level;$bitrate;$txpwr;$rx_invalid_nwid;$rx_invalid_crypt;$rx_invalid_frag;$tx_excessive_retries;$invalid_misc;$missed_beacon;$center_freq;$width";
//$line = $wifi_stats;
//fwrite($log, $line);
//print $line;

$total_devices = count($devices);
$line = "\n\t\t\t\t ---=== ACTIVE DEVICE LIST [$total_devices] ===---\n";
fwrite($log, $line);
print $line;

foreach($devices as $key => $device)
{
	$line =  "\t$device\n";
	fwrite($log, $line);
	print $line;
}

$line ="\n\t\t\t\t---=== SSID SCAN [$ssid_count] ===---\n";
	fwrite($log, $line);
	print $line;
foreach($ssid_scan_results as $key => $result)
{
	/*
OK, need to get width and store that in the database so we know about it, and then also
need to adjust the pimon wifi_info.php ssid scan logic to know what to do with 20,40,80,160Mhz channel widths and what equals cross channels
	
	 */
	if($result["last_seen"] != "0")
		continue;

	unset($scan_center_freq_channel);
	unset($scan_vht_width);
	$scan_ap = $result["ap"];
	$scan_freq = $result["start_freq"];
	$scan_siglev = str_replace("-","",$result["siglevel"]);
	$scan_ssid = $result["ssid"];
	$scan_start_channel = $result["start_channel"];
	$scan_sta_width = $result["sta_width"];
	$ch_utilisation = $result["ch_utilisiation"];
	$station_count = $result["station_count"];
	if($result["vht_width"])
	{
		$scan_center_freq_channel = $result["center_freq_channel"];
		$scan_vht_width = $result["vht_width"];
	}


	// START HERE!!  Need to now see if there is a center freq and if so use that range channel to see if it falls within my current connected range


	$scan_ssid = preg_replace("/\s+/"," ",$scan_ssid);
	//print "scan_freq = $scan_freq\n";
	foreach($wifi_freq_table as $key => $value)
	{
		$scan_channel = $value[0];
		$scan_lowfreq = $value[1];
		$scan_centerfreq = $value[2];
		$scan_highfreq = $value[3];
		$scan_freqwidth = $value[4];

		if($scan_vht_width)
		{
			if($scan_center_freq_channel == $scan_channel)
			{
				$scan_active_channel = $scan_start_channel;
				break;
			}
		}
		else
		{
			if($scan_freq == $scan_centerfreq)
			{
				$scan_active_channel = $scan_start_channel;
				break;
			}
		}
		
	}
	/*
	if($scan_sta_width == "any")
		$da_scan_width = $scan_vht_width;
	else
		$da_scan_width = $scan_sta_width;

	*/

	if(!$scan_center_freq_channel)
		$scan_center_freq_channel = $scan_centerfreq;

//	print "scan_ssid:$scan_ssid scan_lowfreq:$scan_lowfreq scan_highfreq:$scan_highfreq scan_freq:$scan_freq lowfreq:$lowfreq highfreq:$highfreq width:$scan_width scan_freqwidth:$scan_freqwidth scan_center_freq_channel:$scan_center_freq_channel scan_centerfreq: $scan_centerfreq\n";
	if(($scan_lowfreq >= $lowfreq && $scan_lowfreq <= $highfreq) || ($scan_highfreq >= $lowfreq && $scan_highfreq <= $highfreq))
	{
		//$short_ap = strtolower(substr($ap, 0, -2));
		//$short_scan_ap = substr($scan_ap, 0, -2);
		//print "short_ap:$short_ap short_scan_ap:$short_scan_ap\n";
	//	if(strtolower(substr($ap, 0, -2)) == substr($scan_ap, 0, -2)) // Tried turning this off to get the active ssid to help with the graphs
	//		continue; //same ap i'm on so ignoring
		$line = "\tSSID:$scan_ssid ON CHANNEL: $scan_active_channel FREQ: $scan_freq WIDTH: $scan_freqwidth CENTER FREQ CHANNEL: $scan_center_freq_channel OVERLAPS ACTIVE SSID:$ssid CHANNEL: $channel FREQ: $centerfreq [ scan_ap: $scan_ap scan_siglev:$scan_siglev  station_count: $station_count ch_utilisation: $ch_utilisation]\n";
		fwrite($log, $line);
		print $line;
		$ssid_scan[] = "$scan_ssid;$scan_active_channel;$scan_freq;$scan_siglev;$scan_ap;$scan_center_freq_channel;$scan_freqwidth;$station_count;$ch_utilisation";
		//print "MYSQL LINE: $scan_ssid;$scan_active_channel;$scan_freq;$scan_siglev;$scan_ap;$scan_center_freq_channel;$scan_freqwidth\n\n";
		//print "channel $channel! scanfreq: $scan_freq lowfreq: $lowfreq highfreq: $highfreq centerfrq: $centerfreq channel: $channel\n";
		//$line = "\t$result\n";
		//fwrite($log, $line);
		//print $line;
	}
	
	$ssid_scan_all[] = "$scan_ssid;$scan_active_channel;$scan_freq;$scan_siglev;$scan_ap;$scan_center_freq_channel;$scan_freqwidth;$station_count;$ch_utilisation";
}


$line =  "\n===============================================================================================\n";
fwrite($log, $line);
fclose($log);
print $line;


$post = [
'shared_key' => $shared_key,
'hostname' => $pi_hostname,
'timestamp' => $da_date,
'wifi_stats' => base64_encode(serialize($wifi_stats)),
'devices' => base64_encode(serialize($devices)),
'ssid_scan' => base64_encode(serialize($ssid_scan)),
'ssid_scan_all' => base64_encode(serialize($ssid_scan_all))
];


//print "post=$post\n";
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL,"$wipi_server_url");
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);

if($skip_ssl_checking == "yes")
{
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0); // Skip SSL Checking
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0); // Skip SSL Checking
}

$response = curl_exec($ch);
$error = curl_error($ch);
$errno = curl_errno($ch);
curl_close ($ch);
?>

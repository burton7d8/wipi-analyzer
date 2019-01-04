Thank you for your interest in WiPi-Analyzer!

WiPi-Analyzer is a WiFi anaylzer that monitors the wifi network it is joined to [<a href=https://github.com/burton7d8/wipi-analyzer>wipi-analyzer</a>],
and uploads it's collected data to a server [<a href=https://github.com/burton7d8/wipi-analyzer-server>wipi-analyzer-server</a>] where it
can be graphically viewed and anaylzed.
<dl>
        <dt>It keeps track of the following every minute:  </dt>
        <dd>-- The Active channel the Joined SSID is on  </dd>
        <dd>-- The Width of the joined SSID Channel  </dd>
        <dd>-- The reported "Quality" of that SSID </dd> 
        <dd>-- The reported "Signal Level" of that SSID </dd> 
        <dd>-- The current "Bitrate" of the joined SSID </dd> 
        <dd>-- The "tx excessive retries" of the joined SSID </dd> 
</dl>
<dl>
        <dt>-- OVERLAP SSID SCAN Information  </dt>
        <dd>- Known SSIDs that are within the same channel range of the currently joined SSID</dd>
        <dd>- The corresponding APs mac addresses, from the scan</dd>
        <dd>- The corresponding SSIDs name, if available, from the scan</dd>
        <dd>- The corresponding Signal Level of the gathered SSIDS from the scan</dd>
        <dd>- The corresponding channel width of the gathered SSIDS from the scan</dd>
</dl>
<dl>        
        <dt>-- FULL SSID SCAN Information  </dt>
        <dd>- All known SSIDs that are within the 2.4ghz or 5ghz channel ranges</dd>
        <dd>- The corresponding APs mac addresses, from the scan  </dd>
        <dd>- The corresponding SSIDs name, if available, from the scan  </dd>
        <dd>- The corresponding Signal Level of the gathered SSIDS from the scan  </dd>
        <dd>- The corresponding channel width of the gathered SSIDS from the scan  </dd>
</dl>
<dl>
        <dt>-- NETWORK DEVICE SCAN Information from a nmap scan  </dt>
        <dd>[ If a device responds to the nmap, then the following is recorded ]  </dd>
        <dd>- The corresponding devices hostnames, if available  </dd>
        <dd>- The corresponding devices mac addresses  </dd>
</dl>
<dl>
        <dt>-- SSID UTILIZATION INFORMATION  </dt>
        <dd>- For SSIDS that support it, wipi will gather statistics from the [Q]BSS Load Element in the Beacon Frame  </dd>
        <dd>- Number of clients currently connected to the SSID as reported by the AP  </dd>
        <dd>- The current channel utilization as reported by the AP  </dd>
</dl>

It also provides "WiFi Informational Reference Charts" to help you  
debug / understand how the WiFi channels work within 2.4ghz and 5ghz  


I wrote this when I needed a way to better troubleshoot a wireless environment  
to try and resolve intermittent wireless issues.  

I don't claim to be an expert at anything, and I wrote this quickly and for my purposes  
only in the beginning, but then decided to share it with all of you.  Therefore, if you see  
any issues with my code, please don't mock it, just fix it, and let me know so I can learn!  

Thanks,  
~Doug  

To install and use WiPi, follow the INSTALLs under each section:  

<a href=https://github.com/burton7d8/wipi-analyzer>wipi-analyzer</a>  -- the wipi files that go on your raspberry pi [ RASPBERRY PI 3 MODEL B+ recommended since it has 2.4GHz and 5GHz IEEE 802.11.b/g/n/ac wireless LAN ]  

<a href=https://github.com/burton7d8/wipi-analyzer-server>wipi-analyzer-server</a> -- the files that run on your linux server to collect, store, and display the recorded wifi information  

"userspice" -- the files and directions to utilize "UserSpice" "https://userspice.com/" so you can password protect WiPi-Server, [ OPTIONAL ]  
                        - NOTE: this is recommended if you plan to have WiPi-Server public facing!  


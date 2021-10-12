# Faultstat

Faultstat reports the page fault activity of processes
running on a system. The tool supports a 'top' like mode
to dynamically display the top page faulting processes.

Faultstat command line options:

* -a how page fault size changes with up arrow when they increment
* -c get command information from processes comm field
* -d strip directory basename off command information
* -h show help
* -l show long (full) command information
* -p proclist specify a comma separated list of processes to monitor; the process list may contain one or more PIDs or process names
* -s show short command information
* -t top mode, show top page faulting processes by current page fault changes
* -T top mode, show top page faulting processes by total page faults

# Faultstat top mode hotkeys:

* a Toggle page fault change arrow on or off
* s Switch sorting order: Major and Minor, Major, Minor, +Major and +Minor, +Major, +Minor, Swap
* t Toggle between total page fault count and page fault changes
* q Quit

# Example:

show page faults that occur during 60 seconds:

```
sudo faultstat 60 1
Change in page faults (average per second):
     PID  Major   Minor  +Major  +Minor    Swap  User       Command
    7099   2711    4351k      0  290975       0  cking      /usr/lib/thunderbird/thunderbird
    7577  32633    2272k     16   55316       0  cking      /usr/lib/firefox/firefox
    7802  22038  972061       8   62877       0  cking      /usr/lib/firefox/firefox
    6097     57  143886       2     787       0  cking      /usr/bin/gnome-shell
    7681   2767  131395       0     352       0  cking      /usr/lib/firefox/firefox
    9044    111  115413       0      85       0  cking      /usr/lib/firefox/firefox
    5954    219   66363       9     306       0  cking      /usr/lib/xorg/Xorg
     707  25244    3011      77       6       0  root       /lib/systemd/systemd-journald
    8180   6610   16036       0       2       0  cking      /snap/mumble/1675/bin/mumble
    7536    345   17293       0      88       0  cking      /usr/libexec/gnome-terminal-server
    7733     12   12475       0       2       0  cking      /usr/lib/firefox/firefox
    7308     55    9274       0       1       0  cking      /usr/lib/thunderbird/thunderbird
   10412      0     191       0      16       0  root       faultstat
  Total:  92802    8109k    112  410813
```

show Major/Minor faults and change in Major/Minor faults (+Major +Minor fields):
```
faultstat -T
```

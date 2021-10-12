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

show Major/Minor faults and change in Major/Minor faults (+Major +Minor fields):
```
faultstat -T
```

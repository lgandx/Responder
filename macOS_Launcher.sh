#!/usr/bin/env bash
#Responder launcher for MacOS

USAGE="$(basename "$0") [Responder.py arguments...] - Script to automagically re/configure a MacOS environment and launch Responder"

#Environment check
if uname -a | grep -v -q Darwin
	then echo "This script is only for MacOS. On any other OS, run Responder.py directly."
	exit 1
elif csrutil status | grep -q enabled
	then echo "Please disable System Integrity Protection so Responder can stop and start protected services"
	exit 1
elif [[ $# -eq 0 ]]
	then echo "Usage: $USAGE"
	echo "You haven't provided any arguments! Run Responder.py -h for args help."
	exit 1
elif [ "$EUID" -ne 0 ]
	then echo "Managing servces requires root privledges. Please run as root."
	exit 1
fi

TCP_LIST=(21 25 80 88 110 135 139 143 389 445 587 1433 3128 3141)
UDP_LIST=(53 137 138 389 1434 5353 5355)
SVC_LIST=()

#Stop services specified in README.md (if they exist)
if [ -e /System/Library/LaunchDaemons/com.apple.Kerberos.kdc.plist ]
	then launchctl bootout system /System/Library/LaunchDaemons/com.apple.Kerberos.kdc.plist
	SVC_LIST+=(com.apple.Kerberos.kdc)
fi
if [ -e /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist ]
	then launchctl bootout system /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
	SVC_LIST+=(com.apple.mDNSResponder)
fi
if [ -e /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist ]
	then launchctl bootout system /System/Library/LaunchDaemons/com.apple.smbd.plist
	SVC_LIST+=(com.apple.smbd)
fi
if [ -e /System/Library/LaunchDaemons/com.apple.netbiosd.plist ]
	then launchctl bootout system /System/Library/LaunchDaemons/com.apple.netbiosd.plist
	SVC_LIST+=(com.apple.netbiosd)
fi

# Check for any TCP listeners and shut them down
echo "Resolving listening service conflicts..."
for PORT in "${TCP_LIST[@]}"; do
	echo "Checking for TCP listeners on Port $PORT..."
	PROC=$(lsof +c 0 -iTCP:"$PORT" -sTCP:LISTEN -nP | grep -m 1 -v 'launchd\|COMMAND' | cut -d' ' -f1) #Get service name
	if [ -n "$PROC" ]; then
        echo "Found $PROC listening on port $PORT"
		AGENT=$(sudo launchctl list | grep -m 1 "$PROC*" | cut -f3 | sed 's/.reloaded//g') #Find the service plist
		echo "$AGENT"
		echo "Stopping conflicting service: $PROC"
        sudo launchctl bootout system /System/Library/LaunchDaemons/"$AGENT".plist #Shut it down
        SVC_LIST+=("$AGENT") # append killed service to an array
	fi
done

#Do the same for UDP
for PORT in "${UDP_LIST[@]}"; do
	echo "Checking for UDP listeners on port $PORT..."
	PROC=$(sudo lsof +c 0 -iUDP:"$PORT" -nP | grep -E -v '(127|::1)'| grep -m 1 -v 'launchd\|COMMAND' | cut -d' ' -f1)
	if [ -n "$PROC" ]; then
        echo "Found $PROC listening on Port $PORT"
		AGENT=$(sudo launchctl list | grep -m 1 "$PROC*" | cut -f3 | sed 's/.reloaded//g')
		echo "Stopping coflicting service: $PROC"
        sudo launchctl bootout system /System/Library/LaunchDaemons/"$AGENT".plist
        SVC_LIST+=("$AGENT")
	fi
done

# Launch Responder using provided arguments
sudo /usr/bin/env python ./Responder.py "$@"

# Restore stopped services after Responder exits
for AGENT in "${SVC_LIST[@]}"; do
	echo "Restarting stopped service: $AGENT"
	sudo launchctl bootstrap system /System/Library/LaunchDaemons/"$AGENT".plist
done
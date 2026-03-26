#!/usr/bin/env bash
#Responder launcher for MacOS

USAGE="$(basename "$0") [Responder.py arguments...] - Script to automagically re/configure a MacOS environment and launch Responder"

#Environment check
if uname -a | grep -v -q Darwin
	then echo "This script is only for MacOS. On any other OS, run Responder.py directly."
	exit 1
elif [[ $# -eq 0 ]]
	then echo "Usage: $USAGE"
	echo "You haven't provided any arguments! Run Responder.py -h for args help."
	exit 1
elif [ "$EUID" -ne 0 ]
	then echo "Managing services requires root privileges. Please run as root."
	exit 1
fi

# Check SIP status and inform user
echo "Checking System Integrity Protection status..."
if csrutil status | grep -q enabled; then
	echo "==========================================================================="
	echo "WARNING: System Integrity Protection (SIP) is ENABLED"
	echo ""
	echo "With SIP enabled, this script cannot automatically stop macOS services"
	echo "that may conflict with Responder (SMB, mDNSResponder, Kerberos, NetBIOS)."
	echo ""
	echo "You have three options:"
	echo "1. Disable SIP (see README for instructions) for full functionality"
	echo "2. Manually stop conflicting services before running Responder"
	echo "3. Disable conflicting modules in Responder.conf (e.g., set SMB = Off)"
	echo ""
	echo "Continuing with limited functionality in 5 seconds..."
	echo "==========================================================================="
	sleep 5
	SIP_ENABLED=true
else
	echo "✓ System Integrity Protection is disabled. Full service management available."
	SIP_ENABLED=false
fi

TCP_LIST=(21 25 80 88 110 135 139 143 389 445 587 1433 3128 3141)
UDP_LIST=(53 137 138 389 1434 5353 5355)
SVC_LIST=()

#Stop services specified in README.md (if they exist and SIP is disabled)
if [ "$SIP_ENABLED" = false ]; then
	echo "Stopping potentially conflicting macOS services..."
	
	if [ -e /System/Library/LaunchDaemons/com.apple.Kerberos.kdc.plist ]; then
		if launchctl bootout system /System/Library/LaunchDaemons/com.apple.Kerberos.kdc.plist 2>/dev/null; then
			echo "  ✓ Stopped Kerberos.kdc"
			SVC_LIST+=(com.apple.Kerberos.kdc)
		fi
	fi
	
	if [ -e /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist ]; then
		if launchctl bootout system /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist 2>/dev/null; then
			echo "  ✓ Stopped mDNSResponder"
			SVC_LIST+=(com.apple.mDNSResponder)
		fi
	fi
	
	if [ -e /System/Library/LaunchDaemons/com.apple.smbd.plist ]; then
		if launchctl bootout system /System/Library/LaunchDaemons/com.apple.smbd.plist 2>/dev/null; then
			echo "  ✓ Stopped SMB service"
			SVC_LIST+=(com.apple.smbd)
		fi
	fi
	
	if [ -e /System/Library/LaunchDaemons/com.apple.netbiosd.plist ]; then
		if launchctl bootout system /System/Library/LaunchDaemons/com.apple.netbiosd.plist 2>/dev/null; then
			echo "  ✓ Stopped NetBIOS service"
			SVC_LIST+=(com.apple.netbiosd)
		fi
	fi
else
	echo "Skipping service management due to SIP being enabled."
fi

# Check for any TCP listeners and shut them down (if SIP is disabled)
if [ "$SIP_ENABLED" = false ]; then
	echo "Checking for port conflicts..."
	for PORT in "${TCP_LIST[@]}"; do
		PROC=$(lsof +c 0 -iTCP:"$PORT" -sTCP:LISTEN -nP | grep -m 1 -v 'launchd\|COMMAND' | cut -d' ' -f1) #Get service name
		if [ -n "$PROC" ]; then
			echo "  Found $PROC listening on TCP port $PORT"
			AGENT=$(sudo launchctl list | grep -m 1 "$PROC*" | cut -f3 | sed 's/.reloaded//g') #Find the service plist
			if [ -n "$AGENT" ]; then
				echo "  Attempting to stop $AGENT..."
				if sudo launchctl bootout system /System/Library/LaunchDaemons/"$AGENT".plist 2>/dev/null; then
					SVC_LIST+=("$AGENT") # append killed service to an array
					echo "  ✓ Stopped $AGENT"
				else
					echo "  ⚠ Could not stop $AGENT"
				fi
			fi
		fi
	done

	#Do the same for UDP
	for PORT in "${UDP_LIST[@]}"; do
		PROC=$(sudo lsof +c 0 -iUDP:"$PORT" -nP | grep -E -v '(127|::1)'| grep -m 1 -v 'launchd\|COMMAND' | cut -d' ' -f1)
		if [ -n "$PROC" ]; then
			echo "  Found $PROC listening on UDP port $PORT"
			AGENT=$(sudo launchctl list | grep -m 1 "$PROC*" | cut -f3 | sed 's/.reloaded//g')
			if [ -n "$AGENT" ]; then
				echo "  Attempting to stop $AGENT..."
				if sudo launchctl bootout system /System/Library/LaunchDaemons/"$AGENT".plist 2>/dev/null; then
					SVC_LIST+=("$AGENT")
					echo "  ✓ Stopped $AGENT"
				else
					echo "  ⚠ Could not stop $AGENT"
				fi
			fi
		fi
	done
else
	echo "Checking for port conflicts (informational only - cannot stop services with SIP enabled)..."
	CONFLICTS_FOUND=false
	for PORT in "${TCP_LIST[@]}"; do
		PROC=$(lsof +c 0 -iTCP:"$PORT" -sTCP:LISTEN -nP | grep -m 1 -v 'launchd\|COMMAND' | cut -d' ' -f1)
		if [ -n "$PROC" ]; then
			echo "  ⚠ WARNING: $PROC is using TCP port $PORT"
			CONFLICTS_FOUND=true
		fi
	done
	for PORT in "${UDP_LIST[@]}"; do
		PROC=$(sudo lsof +c 0 -iUDP:"$PORT" -nP | grep -E -v '(127|::1)'| grep -m 1 -v 'launchd\|COMMAND' | cut -d' ' -f1)
		if [ -n "$PROC" ]; then
			echo "  ⚠ WARNING: $PROC is using UDP port $PORT"
			CONFLICTS_FOUND=true
		fi
	done
	
	if [ "$CONFLICTS_FOUND" = true ]; then
		echo ""
		echo "Port conflicts detected! Consider:"
		echo "1. Disabling SIP to allow automatic service management"
		echo "2. Editing Responder.conf to disable conflicting modules"
		echo "3. Manually stopping the conflicting services"
		echo ""
	fi
fi

# Launch Responder using provided arguments
echo ""
echo "Launching Responder..."
echo "==========================================================================="
sudo /usr/bin/env python3 ./Responder.py "$@"

# Restore stopped services after Responder exits (only if we stopped them)
if [ ${#SVC_LIST[@]} -gt 0 ]; then
	echo ""
	echo "Restoring stopped services..."
	for AGENT in "${SVC_LIST[@]}"; do
		echo "Restarting service: $AGENT"
		sudo launchctl bootstrap system /System/Library/LaunchDaemons/"$AGENT".plist 2>/dev/null
	done
fi
#!/bin/bash
7z l '/mnt/d/Backup/Personal/Hp/iPhone/DSPloit/iPhone11,8_18.2_22C152_Restore/092-08785-200.dmg' 2>/dev/null | grep -E '^[0-9]{4}' | grep -E 'usr/libexec/[^/]+$|usr/sbin/[^/]+$|usr/bin/[^/]+$|sbin/[^/]+$' | grep -v '_CodeSignature' | awk '{print $NF}' | sort

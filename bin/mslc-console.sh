#!/bin/bash
#
# Project : ModSecurity Lite Console - StopBadBots
# Script  : mslc-console.sh
# Purpose : Main terminal menu for lightweight ModSecurity monitoring tools.
# Author  : Bill Minozzi
# Version : 0.2 beta
# Created : 2026-05-09
# Updated : 2026-05-09

RESET="$(tput sgr0 2>/dev/null)"
BOLD="$(tput bold 2>/dev/null)"
WHITE="$(tput setaf 7 2>/dev/null)"
BLACK_BG="$(tput setab 0 2>/dev/null)"

ACCESS_LOG="/usr/local/apache/logs/access_log"
MODSEC_AUDIT_LOG="/usr/local/apache/logs/modsec_audit.log"

print_title() {
    local cols
    cols=$(tput cols 2>/dev/null || echo 80)
    local title=" ModSecurity Lite Console - StopBadBots "
    local padding=$(( (cols - ${#title}) / 2 ))

    if [ "$padding" -lt 0 ]; then
        padding=0
    fi

    echo
    printf "%s%s%s%*s%s%*s%s\n" "$BOLD" "$WHITE" "$BLACK_BG" "$padding" "" "$title" "$padding" "" "$RESET"
    echo
}

menu_item() {
    printf "  %3s)  %s\n" "$1" "$2"
}

pause_screen() {
    echo
    read -p "Press Enter to continue..." _
}

show_about() {
    clear
    print_title

    echo "ModSecurity Lite Console - StopBadBots"
    echo
    echo "Version : 0.2 beta"
    echo "Author  : Bill Minozzi"
    echo
    echo "Lightweight ModSecurity monitoring console"
    echo "for Apache / CWAF / StopBadBots environments."
    echo
    echo "GitHub:"
    echo "https://github.com/sergiominozzi"
    echo
    echo "Visit the project page for:"
    echo "- Updates"
    echo "- Documentation"
    echo "- Security tools"
    echo "- WordPress plugins"
    echo
    echo "Thank you for using ModSecurity Lite Console - StopBadBots."

    pause_screen
}

main_menu() {
    while true; do
        clear
        print_title

        menu_item "1" "Top 10 blocked IPs (403)"
        menu_item "2" "Live ModSecurity audit monitor"
        menu_item "3" "ModSecurity totals by date"
        menu_item "4" "ModSecurity rules triggered today"
        menu_item "5" "ModSecurity rules triggered yesterday"
        menu_item "6" "Top URLs blocked today"
        menu_item "7" "About"
        menu_item "8" "Exit"

        echo
        read -p "Choose an option [1-8]: " option

        case "$option" in
            1)

                watch -n 20 'echo "ModSecurity Lite Console - Top 10 Blocked IPs (403)"; echo "Updated: $(date)"; echo " "; echo "Press Ctrl+C to stop."; echo; printf "%-10s | %s\n" "Number" "IP"; echo "----------------------------------------"; tail -n 300 /usr/local/apache/logs/access_log | grep " 403 " | awk '\''{print $1}'\'' | sort | uniq -c | awk '\''$1 > 2'\'' | sort -nr | head -10'
                ;;
            2)
                echo "--- [2] Live ModSecurity audit monitor ---"
                python3 /usr/local/bin/mslc-live-monitor.py
                pause_screen
                ;;
            3)
                echo "--- [3] ModSecurity totals by date ---"
                python3 /usr/local/bin/mslc-rule-totals.py
                pause_screen
                ;;
            4)
                echo "--- [4] ModSecurity rules triggered today ---"
                echo
                echo "Processing logs, please wait..."
                echo
                python3 /usr/local/bin/mslc-rules-today.py
                pause_screen
                ;;
            5)
                echo "--- [5] ModSecurity rules triggered yesterday ---"
                echo
                echo "Processing logs, please wait..."
                echo
                python3 /usr/local/bin/mslc-rules-yesterday.py
                pause_screen
                ;;
            6)
                echo "--- [6] Top URLs blocked today ---"
                echo
                echo "Processing logs, please wait..."
                echo
                python3 /usr/local/bin/mslc-top-urls-today.py
                pause_screen
                ;;

            7)
                show_about
                ;;
            8)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo "Invalid option. Please try again."
                sleep 2
                ;;
        esac
    done
}

main_menu

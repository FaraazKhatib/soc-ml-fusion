#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════╗"
echo "║     SOC ML Brute Force Detector              ║"
echo "║     IITB Trust Lab — Summer of Code 2026     ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}[1/4] Checking Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] python3 not found.${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Python found.${NC}"

echo -e "${YELLOW}[2/4] Installing dependencies...${NC}"
pip3 install scikit-learn --quiet
echo -e "${GREEN}[OK] Dependencies installed.${NC}"

echo -e "${YELLOW}[3/4] Checking log file...${NC}"
LOG_PATH=$(grep 'AUTH_LOG_FILE' ml_fusion.py | head -1 | sed "s/.*= *['\"]//;s/['\"].*//")
echo -e "    Log file path: ${BLUE}${LOG_PATH}${NC}"
if [ ! -f "$LOG_PATH" ]; then
    echo -e "${RED}[ERROR] Log file not found at: ${LOG_PATH}${NC}"
    echo -e "${YELLOW}  Fix: Open ml_fusion.py and change AUTH_LOG_FILE to your path.${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Log file found.${NC}"

echo -e "${YELLOW}[4/4] Starting detector...${NC}"
echo ""
python3 -u ml_fusion.py

#!/usr/bin/env python3
import schedule
import time
import asyncio
from scanner_integration import ScannerIntegration

class AutomatedScanner:
    def __init__(self, api_key):
        self.scanner = ScannerIntegration()
        self.api_key = api_key
    
    def scan_daily(self):
        """Run daily scans"""
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting daily scan...")
        asyncio.run(self.scanner.full_pipeline(sample_size=100))
        print("✅ Daily scan complete")
    
    def scan_weekly(self):
        """Run comprehensive weekly scans"""
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting weekly scan...")
        asyncio.run(self.scanner.full_pipeline(sample_size=500))
        print("✅ Weekly scan complete")
    
    def start_scheduler(self):
        """Start the scheduler"""
        schedule.every().day.at("03:00").do(self.scan_daily)
        schedule.every().week.monday.at("09:00").do(self.scan_weekly)
        
        print("✅ Scanner scheduled")
        print("   Daily: 3:00 AM")
        print("   Weekly: Monday 9:00 AM")
        
        while True:
            schedule.run_pending()
            time.sleep(60)

if __name__ == "__main__":
    scanner = AutomatedScanner(api_key="vata_key_xxx")
    scanner.start_scheduler()

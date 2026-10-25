#!/usr/bin/env python3
import schedule
import time
import asyncio
from scanner_integration import ScannerIntegration

class AutomatedScanner:
    """Scheduler for SYNTHETIC demo data only.

    `ScannerIntegration.run_scan()` fabricates findings; it never probes a
    server. Scheduling it is only meaningful against a demo dashboard, so the
    synthetic flag has to be passed explicitly at construction time.
    """

    def __init__(self, api_key, demo=False):
        self.scanner = ScannerIntegration()
        self.api_key = api_key
        self.demo = demo
    
    def scan_daily(self):
        """Run daily scans"""
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting daily scan...")
        asyncio.run(self.scanner.full_pipeline(sample_size=100, demo=self.demo))
        print("✅ Daily demo scan complete (synthetic findings)")
    
    def scan_weekly(self):
        """Run comprehensive weekly scans"""
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting weekly scan...")
        asyncio.run(self.scanner.full_pipeline(sample_size=500, demo=self.demo))
        print("✅ Weekly demo scan complete (synthetic findings)")
    
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
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Schedule SYNTHETIC demo findings. Nothing is scanned.")
    parser.add_argument("--demo", action="store_true", required=True,
                        help="required acknowledgement that the findings are fake")
    args = parser.parse_args()
    scanner = AutomatedScanner(api_key="vata_key_xxx", demo=args.demo)
    scanner.start_scheduler()
    sys.exit(0)

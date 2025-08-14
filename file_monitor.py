#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
مراقب التغييرات في النظام - File Integrity Monitor
إصدار: 2.0
"""

import hashlib
import os
import time
import platform
from pathlib import Path
from colorama import init, Fore

init()  # تهيئة colorama للألوان في الطرفية

class FileMonitor:
    def __init__(self, target_path):
        """
        تهيئة مراقب الملفات
        :param target_path: مسار الملف أو المجلد للمراقبة
        """
        self.target_path = Path(target_path).absolute()
        self.baseline = {}
        self.log_file = "file_monitor.log"
        self.os_type = platform.system()
        
        # إنشاء ملف السجل إذا لم يكن موجوداً
        if not Path(self.log_file).exists():
            with open(self.log_file, 'w') as f:
                f.write("File Integrity Monitor Log\n")
        
        self.log(f"Starting monitoring on {self.target_path}", "INFO")

    def calculate_hash(self, file_path):
        """
        حساب البصمة الرقمية للملف باستخدام SHA-256
        :param file_path: مسار الملف
        :return: البصمة الرقمية أو None في حالة الخطأ
        """
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256()
                while chunk := f.read(8192):  # قراءة الملف على شكل قطع للحفاظ على الذاكرة
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except PermissionError:
            self.log(f"Permission denied: {file_path}", "WARNING")
            return None
        except Exception as e:
            self.log(f"Error reading {file_path}: {str(e)}", "ERROR")
            return None
    
    def create_baseline(self):
        """إنشاء خط أساسي للبصمات الرقمية للملفات"""
        try:
            self.log("Creating baseline hashes...", "INFO")
            
            if self.target_path.is_file():
                file_hash = self.calculate_hash(self.target_path)
                if file_hash:
                    self.baseline[str(self.target_path)] = {
                        'hash': file_hash,
                        'size': self.target_path.stat().st_size,
                        'mtime': self.target_path.stat().st_mtime
                    }
            elif self.target_path.is_dir():
                for root, _, files in os.walk(self.target_path):
                    for file in files:
                        path = Path(root) / file
                        file_hash = self.calculate_hash(path)
                        if file_hash:
                            self.baseline[str(path)] = {
                                'hash': file_hash,
                                'size': path.stat().st_size,
                                'mtime': path.target_path.stat().st_mtime
                            }
            
            self.log(f"Baseline created with {len(self.baseline)} files", "SUCCESS")
            return True
        except Exception as e:
            self.log(f"Error creating baseline: {str(e)}", "ERROR")
            return False
    
    def monitor(self, interval=10):
        """
        بدء مراقبة التغييرات
        :param interval: الفترة الزمنية بين الفحوصات (بالثواني)
        """
        try:
            self.log(f"Starting monitoring with {interval} seconds interval", "INFO")
            
            while True:
                time.sleep(interval)
                current_state = {}
                changes_detected = False
                
                # مسح الملفات الحالية
                if self.target_path.is_file():
                    file_hash = self.calculate_hash(self.target_path)
                    if file_hash:
                        current_state[str(self.target_path)] = {
                            'hash': file_hash,
                            'size': self.target_path.stat().st_size,
                            'mtime': self.target_path.stat().st_mtime
                        }
                elif self.target_path.is_dir():
                    for root, _, files in os.walk(self.target_path):
                        for file in files:
                            path = Path(root) / file
                            file_hash = self.calculate_hash(path)
                            if file_hash:
                                current_state[str(path)] = {
                                    'hash': file_hash,
                                    'size': path.stat().st_size,
                                    'mtime': path.stat().st_mtime
                                }
                
                # الكشف عن الملفات الجديدة
                for file in current_state:
                    if file not in self.baseline:
                        self.log(f"New file detected: {file}", "WARNING")
                        changes_detected = True
                
                # الكشف عن الملفات المحذوفة
                for file in self.baseline:
                    if file not in current_state:
                        self.log(f"File deleted: {file}", "WARNING")
                        changes_detected = True
                
                # الكشف عن التغييرات في الملفات الموجودة
                for file in current_state:
                    if file in self.baseline:
                        old_data = self.baseline[file]
                        new_data = current_state[file]
                        
                        # الكشف عن تغيير المحتوى
                        if new_data['hash'] != old_data['hash']:
                            self.log(f"File content changed: {file}", "WARNING")
                            changes_detected = True
                        
                        # الكشف عن تغيير الحجم
                        elif new_data['size'] != old_data['size']:
                            self.log(f"File size changed: {file}", "WARNING")
                            changes_detected = True
                        
                        # الكشف عن تغيير وقت التعديل
                        elif new_data['mtime'] != old_data['mtime']:
                            self.log(f"File modification time changed: {file}", "WARNING")
                            changes_detected = True
                
                if changes_detected:
                    self.baseline = current_state  # تحديث الخط الأساسي
                
        except KeyboardInterrupt:
            self.log("Monitoring stopped by user", "INFO")
        except Exception as e:
            self.log(f"Monitoring error: {str(e)}", "ERROR")
    
    def log(self, message, level="INFO"):
        """تسجيل الأحداث مع تصنيف مستوى الخطورة"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # ألوان حسب مستوى الخطورة
        colors = {
            "INFO": Fore.BLUE,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "SUCCESS": Fore.GREEN
        }
        
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # طباعة ملونة في الطرفية
        print(colors.get(level, Fore.WHITE) + log_entry + Fore.RESET)
        
        # تسجيل في الملف (بدون ألوان)
        with open(self.log_file, "a", encoding='utf-8') as f:
            f.write(log_entry + "\n")

def check_os_compatibility():
    """التحقق من توافق النظام"""
    system = platform.system()
    if system not in ['Linux', 'Windows']:
        print(Fore.YELLOW + "Warning: This tool is primarily tested on Linux and Windows" + Fore.RESET)

if __name__ == "__main__":
    import argparse
    
    check_os_compatibility()
    
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor - Track changes to critical files",
        epilog="Example: python file_monitor.py /etc"
    )
    parser.add_argument("path", help="Path to file or directory to monitor")
    parser.add_argument("-i", "--interval", type=int, default=10,
                       help="Monitoring interval in seconds (default: 10)")
    
    args = parser.parse_args()
    
    monitor = FileMonitor(args.path)
    if monitor.create_baseline():
        monitor.monitor(args.interval)



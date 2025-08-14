#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
كسر كلمات المرور - Password Cracker
إصدار: 2.0
"""

import hashlib
import itertools
import string
import time
import platform
from colorama import init, Fore

init()

class PasswordCracker:
    def __init__(self):
        self.log_file = "password_cracker.log"
        self.os_type = platform.system()
        self.log("Password Cracker initialized", "INFO")

    def hash_password(self, password, hash_type="sha256"):
        """
        تشفير كلمة المرور باستخدام خوارزمية معينة
        :param password: كلمة المرور المراد تشفيرها
        :param hash_type: نوع التشفير (md5, sha1, sha256, sha512)
        :return: كلمة المرور المشفرة
        """
        if hash_type == "md5":
            return hashlib.md5(password.encode()).hexdigest()
        elif hash_type == "sha1":
            return hashlib.sha1(password.encode()).hexdigest()
        elif hash_type == "sha256":
            return hashlib.sha256(password.encode()).hexdigest()
        elif hash_type == "sha512":
            return hashlib.sha512(password.encode()).hexdigest()
        else:
            self.log(f"Unsupported hash type: {hash_type}", "ERROR")
            return None

    def crack_bruteforce(self, hashed_password, hash_type, charset, max_length):
        """
        كسر كلمة المرور باستخدام هجوم القوة الغاشمة (Brute-force)
        :param hashed_password: كلمة المرور المشفرة المستهدفة
        :param hash_type: نوع التشفير المستخدم
        :param charset: مجموعة الأحرف المستخدمة في الهجوم
        :param max_length: أقصى طول لكلمة المرور
        :return: كلمة المرور المكسورة أو None
        """
        self.log(f"Starting brute-force attack (max_length={max_length}, charset={charset})...", "INFO")
        start_time = time.time()
        
        for length in range(1, max_length + 1):
            for attempt in itertools.product(charset, repeat=length):
                word = "".join(attempt)
                hashed_word = self.hash_password(word, hash_type)
                if hashed_word == hashed_password:
                    end_time = time.time()
                    self.log(f"Password cracked: {word} (Time: {end_time - start_time:.2f}s)", "SUCCESS")
                    return word
        
        end_time = time.time()
        self.log(f"Brute-force attack finished. Password not found. (Time: {end_time - start_time:.2f}s)", "WARNING")
        return None

    def crack_dictionary(self, hashed_password, hash_type, dictionary_path):
        """
        كسر كلمة المرور باستخدام هجوم القاموس (Dictionary Attack)
        :param hashed_password: كلمة المرور المشفرة المستهدفة
        :param hash_type: نوع التشفير المستخدم
        :param dictionary_path: مسار ملف القاموس
        :return: كلمة المرور المكسورة أو None
        """
        self.log(f"Starting dictionary attack using {dictionary_path}...", "INFO")
        start_time = time.time()
        
        try:
            with open(dictionary_path, "r", encoding="latin-1") as f:
                for line in f:
                    word = line.strip()
                    hashed_word = self.hash_password(word, hash_type)
                    if hashed_word == hashed_password:
                        end_time = time.time()
                        self.log(f"Password cracked: {word} (Time: {end_time - start_time:.2f}s)", "SUCCESS")
                        return word
        except FileNotFoundError:
            self.log(f"Dictionary file not found: {dictionary_path}", "ERROR")
            return None
        except Exception as e:
            self.log(f"Error reading dictionary file: {str(e)}", "ERROR")
            return None
        
        end_time = time.time()
        self.log(f"Dictionary attack finished. Password not found. (Time: {end_time - start_time:.2f}s)", "WARNING")
        return None

    def log(self, message, level="INFO"):
        """تسجيل الأحداث مع تصنيف مستوى الخطورة"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        colors = {
            "INFO": Fore.BLUE,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "SUCCESS": Fore.GREEN
        }
        
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        print(colors.get(level, Fore.WHITE) + log_entry + Fore.RESET)
        
        with open(self.log_file, "a", encoding=\'utf-8\') as f:
            f.write(log_entry + "\n")

def check_os_compatibility():
    """التحقق من توافق النظام"""
    system = platform.system()
    if system not in [\'Linux\', \'Windows\']:
        print(Fore.YELLOW + "Warning: This tool is primarily tested on Linux and Windows" + Fore.RESET)

if __name__ == "__main__":
    import argparse
    
    check_os_compatibility()
    
    parser = argparse.ArgumentParser(
        description="Password Cracker - Perform brute-force or dictionary attacks",
        epilog="Example: python password_cracker.py --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 --type sha256 --bruteforce --charset lower --max-length 4"
    )
    parser.add_argument("--hash", required=True, help="Hashed password to crack")
    parser.add_argument("--type", default="sha256", choices=["md5", "sha1", "sha256", "sha512"], help="Hash type (default: sha256)")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bruteforce", action="store_true", help="Perform brute-force attack")
    group.add_argument("--dictionary", help="Path to dictionary file for dictionary attack")
    
    parser.add_argument("--charset", default="lower", choices=["lower", "upper", "digits", "all"],
                       help="Character set for brute-force (lower, upper, digits, all)")
    parser.add_argument("--max-length", type=int, default=4, help="Max length for brute-force (default: 4)")
    
    args = parser.parse_args()
    
    cracker = PasswordCracker()
    
    charset_map = {
        "lower": string.ascii_lowercase,
        "upper": string.ascii_uppercase,
        "digits": string.digits,
        "all": string.ascii_letters + string.digits + string.punctuation
    }
    
    if args.bruteforce:
        cracker.crack_bruteforce(args.hash, args.type, charset_map[args.charset], args.max_length)
    elif args.dictionary:
        cracker.crack_dictionary(args.hash, args.type, args.dictionary)



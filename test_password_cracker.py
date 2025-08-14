import unittest
import os
from EthicalSecurityTools.tools.password_cracker import PasswordCracker

class TestPasswordCracker(unittest.TestCase):
    def setUp(self):
        self.cracker = PasswordCracker()
        self.cracker.log_file = "test_password_cracker.log" # Redirect log for testing
        if os.path.exists(self.cracker.log_file):
            os.remove(self.cracker.log_file)

        self.test_dict_file = "test_dictionary.txt"
        with open(self.test_dict_file, "w") as f:
            f.write("password\n")
            f.write("123456\n")
            f.write("qwerty\n")

    def tearDown(self):
        if os.path.exists(self.cracker.log_file):
            os.remove(self.cracker.log_file)
        if os.path.exists(self.test_dict_file):
            os.remove(self.test_dict_file)

    def test_hash_password_md5(self):
        self.assertEqual(self.cracker.hash_password("test", "md5"), "098f6bcd4621d373cade4e832627b4f6")

    def test_hash_password_sha256(self):
        self.assertEqual(self.cracker.hash_password("test", "sha256"), "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")

    def test_crack_bruteforce_success(self):
        # Hash of 'abc' using sha256
        hashed_password = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        cracked_password = self.cracker.crack_bruteforce(hashed_password, "sha256", "abc", 3)
        self.assertEqual(cracked_password, "abc")

    def test_crack_bruteforce_fail(self):
        # Hash of 'test' using sha256, but charset is only 'abc'
        hashed_password = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        cracked_password = self.cracker.crack_bruteforce(hashed_password, "sha256", "abc", 3)
        self.assertIsNone(cracked_password)

    def test_crack_dictionary_success(self):
        # Hash of 'password' using md5
        hashed_password = "5f4dcc3b5aa765d61d8327deb882cf99"
        cracked_password = self.cracker.crack_dictionary(hashed_password, "md5", self.test_dict_file)
        self.assertEqual(cracked_password, "password")

    def test_crack_dictionary_fail(self):
        # Hash of 'unknown' using md5
        hashed_password = "5f4dcc3b5aa765d61d8327deb882cf99_unknown"
        cracked_password = self.cracker.crack_dictionary(hashed_password, "md5", self.test_dict_file)
        self.assertIsNone(cracked_password)

    def test_crack_dictionary_file_not_found(self):
        cracked_password = self.cracker.crack_dictionary("somehash", "md5", "non_existent_file.txt")
        self.assertIsNone(cracked_password)
        with open(self.cracker.log_file, "r") as f:
            log_content = f.read()
            self.assertIn("Dictionary file not found", log_content)

if __name__ == '__main__':
    unittest.main()


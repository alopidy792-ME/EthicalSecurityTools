import unittest
import os
import time
from pathlib import Path
from EthicalSecurityTools.tools.file_monitor import FileMonitor

class TestFileMonitor(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path("test_monitor_dir")
        self.test_file = self.test_dir / "test_file.txt"
        self.test_dir.mkdir(exist_ok=True)
        with open(self.test_file, "w") as f:
            f.write("initial content")
        self.monitor = FileMonitor(self.test_dir)
        self.monitor.log_file = "test_file_monitor.log" # Redirect log for testing
        if Path(self.monitor.log_file).exists():
            os.remove(self.monitor.log_file)

    def tearDown(self):
        if self.test_dir.exists():
            import shutil
            shutil.rmtree(self.test_dir)
        if Path(self.monitor.log_file).exists():
            os.remove(self.monitor.log_file)

    def test_calculate_hash(self):
        test_hash = self.monitor.calculate_hash(self.test_file)
        self.assertIsNotNone(test_hash)
        self.assertEqual(len(test_hash), 64) # SHA256 hash length

    def test_create_baseline(self):
        self.assertTrue(self.monitor.create_baseline())
        self.assertIn(str(self.test_file), self.monitor.baseline)

    def test_file_modification_detection(self):
        self.monitor.create_baseline()
        time.sleep(1) # Ensure mtime changes
        with open(self.test_file, "a") as f:
            f.write(" new content")
        
        # Simulate monitoring cycle (not full monitor loop)
        current_state = {}
        file_hash = self.monitor.calculate_hash(self.test_file)
        if file_hash:
            current_state[str(self.test_file)] = {
                'hash': file_hash,
                'size': self.test_file.stat().st_size,
                'mtime': self.test_file.stat().st_mtime
            }
        
        # Manually check for changes based on monitor's logic
        changes_detected = False
        old_data = self.monitor.baseline[str(self.test_file)]
        new_data = current_state[str(self.test_file)]

        if new_data['hash'] != old_data['hash']:
            changes_detected = True
        elif new_data['size'] != old_data['size']:
            changes_detected = True
        elif new_data['mtime'] != old_data['mtime']:
            changes_detected = True
        
        self.assertTrue(changes_detected)
        with open(self.monitor.log_file, "r") as f:
            log_content = f.read()
            self.assertIn("File content changed", log_content)

    def test_new_file_detection(self):
        self.monitor.create_baseline()
        new_file = self.test_dir / "new_file.txt"
        with open(new_file, "w") as f:
            f.write("new file content")
        
        # Simulate monitoring cycle
        current_state = {}
        for root, _, files in os.walk(self.test_dir):
            for file in files:
                path = Path(root) / file
                file_hash = self.monitor.calculate_hash(path)
                if file_hash:
                    current_state[str(path)] = {
                        'hash': file_hash,
                        'size': path.stat().st_size,
                        'mtime': path.stat().st_mtime
                    }
        
        changes_detected = False
        if str(new_file) not in self.monitor.baseline:
            changes_detected = True

        self.assertTrue(changes_detected)
        with open(self.monitor.log_file, "r") as f:
            log_content = f.read()
            self.assertIn("New file detected", log_content)

    def test_deleted_file_detection(self):
        self.monitor.create_baseline()
        os.remove(self.test_file)
        
        # Simulate monitoring cycle
        current_state = {}
        # No files in current_state if test_dir is empty or only new files are added
        
        changes_detected = False
        if str(self.test_file) not in current_state:
            if str(self.test_file) in self.monitor.baseline:
                changes_detected = True

        self.assertTrue(changes_detected)
        with open(self.monitor.log_file, "r") as f:
            log_content = f.read()
            self.assertIn("File deleted", log_content)

if __name__ == '__main__':
    unittest.main()


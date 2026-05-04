from pykeepass import PyKeePass
import os

data_dir = 'c:/APPS/KeepassViewer/data'
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

file_path = os.path.join(data_dir, 'tech_passwords.kdbx')
if os.path.exists(file_path):
    os.remove(file_path)

kp = PyKeePass(file_path, password='admin')
group = kp.add_group(kp.root_group, 'Sample Group')
kp.add_entry(group, 'Sample Entry', 'user', 'pass', url='http://example.com')
kp.save()
print(f"Created {file_path}")

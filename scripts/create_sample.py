from pykeepass import create_database
import os

def create_sample_kdbx(file_path, password):
    if os.path.exists(file_path):
        return
    
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    kp = create_database(file_path, password=password)
    
    # Add some sample entries
    group = kp.add_group(kp.root_group, 'Technology')
    kp.add_entry(group, 'Server Admin', 'admin', 'password123', url='http://10.0.0.1')
    kp.add_entry(group, 'GitHub Team', 'tech-lead', 'git-pass-789', url='https://github.com')
    
    kp.save()
    print(f"Sample KeePass file created at {file_path}")

if __name__ == "__main__":
    create_sample_kdbx('data/sample.kdbx', 'master')

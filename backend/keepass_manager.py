import os
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
import threading

class KeePassManager:
    def __init__(self, file_path, password=None):
        self.file_path = file_path
        self.password = password
        self.kp = None
        self.lock = threading.Lock()

    def open(self, password):
        try:
            self.kp = PyKeePass(self.file_path, password=password)
            self.password = password
            return True
        except CredentialsError:
            return False
        except Exception as e:
            print(f"Error opening KeePass file: {e}")
            return False

    def get_entries(self):
        if not self.kp:
            return []
        
        entries = []
        for entry in self.kp.entries:
            entries.append({
                "uuid": str(entry.uuid),
                "title": entry.title,
                "username": entry.username,
                "password": entry.password,
                "url": entry.url,
                "notes": entry.notes,
                "icon": entry.icon,
                "group": entry.group.name if entry.group else "Root",
                "group_uuid": str(entry.group.uuid) if entry.group else None
            })
        return entries

    def get_groups(self):
        if not self.kp:
            return []
        
        def recurse_groups(group, level=0):
            result = {
                "uuid": str(group.uuid),
                "name": group.name,
                "level": level,
                "icon": group.icon,
                "subgroups": [recurse_groups(child, level + 1) for child in group.subgroups]
            }
            return result

        # Devolvemos la estructura jerárquica completa desde la raíz
        return recurse_groups(self.kp.root_group)

    def add_group(self, name):
        with self.lock:
            self.kp.add_group(self.kp.root_group, name)
            self.kp.save()
            return True

    def add_entry(self, group_name, title, username, password, url=None, notes=None):
        with self.lock:
            group = self.kp.find_groups(name=group_name, first=True)
            if not group:
                group = self.kp.root_group
            
            self.kp.add_entry(group, title, username, password, url=url, notes=notes)
            self.kp.save()
            return True

    def update_entry(self, entry_uuid, title=None, username=None, password=None, url=None, notes=None):
        with self.lock:
            entry = self.kp.find_entries(uuid=entry_uuid, first=True)
            if entry:
                if title is not None: entry.title = title
                if username is not None: entry.username = username
                if password is not None: entry.password = password
                if url is not None: entry.url = url
                if notes is not None: entry.notes = notes
                self.kp.save()
                return True
            return False

    def delete_entry(self, entry_uuid):
        with self.lock:
            entry = self.kp.find_entries(uuid=entry_uuid, first=True)
            if entry:
                self.kp.delete_entry(entry)
                self.kp.save()
                return True
            return False

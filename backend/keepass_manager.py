import uuid
import threading
import logging

from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

logger = logging.getLogger("kpv.keepass")


class KeePassManager:
    def __init__(self, file_path, password=None):
        self.file_path = file_path
        self.password = password
        self.kp = None
        self.lock = threading.RLock()

    def open(self, password):
        try:
            self.kp = PyKeePass(self.file_path, password=password)
            self.password = password
            return True
        except CredentialsError:
            return False
        except Exception as e:
            logger.error("Error opening KeePass file: %s", e)
            return False

    def close(self):
        """Lock the database in memory."""
        with self.lock:
            self.kp = None
            self.password = None

    @property
    def is_open(self):
        return self.kp is not None

    # ----------------------------------------------------------------- #
    # Reads
    # ----------------------------------------------------------------- #
    def get_entries(self, include_secrets=False):
        """Return entries. Passwords are omitted unless include_secrets=True."""
        with self.lock:
            if not self.kp:
                return []
            entries = []
            for entry in self.kp.entries:
                item = {
                    "uuid": str(entry.uuid),
                    "title": entry.title or "",
                    "username": entry.username or "",
                    "url": entry.url or "",
                    "notes": entry.notes or "",
                    "icon": entry.icon,
                    "has_password": bool(entry.password),
                    "group": entry.group.name if entry.group else "Root",
                    "group_uuid": str(entry.group.uuid) if entry.group else None,
                }
                if include_secrets:
                    item["password"] = entry.password
                entries.append(item)
            return entries

    def get_password(self, entry_uuid):
        """Return a single entry's password on demand (for reveal/copy)."""
        with self.lock:
            if not self.kp:
                return None
            entry = self.kp.find_entries(uuid=uuid.UUID(entry_uuid), first=True)
            return entry.password if entry else None

    def get_groups(self):
        with self.lock:
            if not self.kp:
                return {}

            def recurse(group, level=0):
                return {
                    "uuid": str(group.uuid),
                    "name": group.name,
                    "level": level,
                    "icon": group.icon,
                    "subgroups": [recurse(c, level + 1) for c in group.subgroups],
                }

            return recurse(self.kp.root_group)

    # ----------------------------------------------------------------- #
    # Groups
    # ----------------------------------------------------------------- #
    def _find_group_by_uuid(self, group_uuid):
        if not group_uuid:
            return self.kp.root_group
        return self.kp.find_groups(uuid=uuid.UUID(group_uuid), first=True)

    def add_group(self, name, parent_uuid=None):
        with self.lock:
            parent = self._find_group_by_uuid(parent_uuid) or self.kp.root_group
            self.kp.add_group(parent, name)
            self.kp.save()
            return True

    def delete_group(self, group_uuid):
        with self.lock:
            group = self.kp.find_groups(uuid=uuid.UUID(group_uuid), first=True)
            if not group or group == self.kp.root_group:
                return False
            self.kp.delete_group(group)
            self.kp.save()
            return True

    # ----------------------------------------------------------------- #
    # Entries
    # ----------------------------------------------------------------- #
    def add_entry(self, group_uuid, title, username, password, url=None, notes=None):
        with self.lock:
            group = self._find_group_by_uuid(group_uuid) or self.kp.root_group
            self.kp.add_entry(group, title, username, password, url=url, notes=notes)
            self.kp.save()
            return True

    def update_entry(self, entry_uuid, title=None, username=None, password=None,
                     url=None, notes=None, group_uuid=None):
        with self.lock:
            entry = self.kp.find_entries(uuid=uuid.UUID(entry_uuid), first=True)
            if not entry:
                return False
            if title is not None:
                entry.title = title
            if username is not None:
                entry.username = username
            # Empty password means "leave unchanged" so the UI never has to hold it
            if password:
                entry.password = password
            if url is not None:
                entry.url = url
            if notes is not None:
                entry.notes = notes
            if group_uuid:
                target = self._find_group_by_uuid(group_uuid)
                if target and target != entry.group:
                    self.kp.move_entry(entry, target)
            self.kp.save()
            return True

    def delete_entry(self, entry_uuid):
        with self.lock:
            entry = self.kp.find_entries(uuid=uuid.UUID(entry_uuid), first=True)
            if not entry:
                return False
            self.kp.delete_entry(entry)
            self.kp.save()
            return True

import json
import logging
import os
from datetime import datetime

import rich
import yaml  # type: ignore
from filelock import FileLock
from pydantic import ValidationError

from mcp_scan.models import Entity, ScannedEntities, ScannedEntity, entity_type_to_str, hash_entity

# Set up logger for this module
logger = logging.getLogger(__name__)


class Storage:
    def __init__(self, path: str):
        logger.debug("Initializing Storage with path: %s", path)
        self.path = os.path.expanduser(path)

        logger.debug("Expanded path: %s", self.path)
        self.scanned_entities: ScannedEntities = ScannedEntities({})
        self.whitelist: dict[str, str] = {}

        self.detect_and_convert_legacy_storage()
        self.init_from_path()
        os.makedirs(self.path, exist_ok=True)
        self._lock_path = os.path.join(self.path, ".mcp-scan.lock")
        self._lock = FileLock(self._lock_path, timeout=10)

    def detect_and_convert_legacy_storage(self):
        if os.path.isfile(self.path):
            rich.print(f"[bold]Legacy storage file detected at {self.path}, converting to new format[/bold]")
            # legacy format
            with open(self.path) as f:
                legacy_data = json.load(f)
            if "__whitelist" in legacy_data:
                self.whitelist = legacy_data["__whitelist"]
                del legacy_data["__whitelist"]

            try:
                logger.debug("Loading legacy format file")
                with open(self.path) as f:
                    legacy_data = json.load(f)
                if "__whitelist" in legacy_data:
                    logger.debug("Found whitelist in legacy data with %d entries", len(legacy_data["__whitelist"]))
                    self.whitelist = legacy_data["__whitelist"]
                    del legacy_data["__whitelist"]
                try:
                    self.scanned_entities = ScannedEntities.model_validate(legacy_data)
                    logger.info("Successfully loaded legacy scanned entities data")
                except ValidationError as e:
                    error_msg = f"Could not load legacy storage file {self.path}: {e}"
                    logger.error(error_msg)
                    rich.print(f"[bold red]{error_msg}[/bold red]")
                os.remove(self.path)
                logger.info("Removed legacy storage file after conversion")
            except Exception:
                logger.exception("Error processing legacy storage file: %s", self.path)

    def init_from_path(self):
        if os.path.exists(self.path) and os.path.isdir(self.path):
            logger.debug("Path exists and is a directory: %s", self.path)
            scanned_entities_path = os.path.join(self.path, "scanned_entities.json")

            if os.path.exists(scanned_entities_path):
                logger.debug("Loading scanned entities from: %s", scanned_entities_path)
                with open(scanned_entities_path) as f:
                    try:
                        self.scanned_entities = ScannedEntities.model_validate_json(f.read())
                        logger.info("Successfully loaded scanned entities data")
                    except ValidationError as e:
                        error_msg = f"Could not load scanned entities file {scanned_entities_path}: {e}"
                        logger.error(error_msg)
                        rich.print(f"[bold red]{error_msg}[/bold red]")
            whitelist_path = os.path.join(self.path, "whitelist.json")
            if os.path.exists(whitelist_path):
                logger.debug("Loading whitelist from: %s", whitelist_path)
                with open(whitelist_path) as f:
                    self.whitelist = json.load(f)
                    logger.info("Successfully loaded whitelist with %d entries", len(self.whitelist))

    def reset_whitelist(self) -> None:
        logger.info("Resetting whitelist")
        self.whitelist = {}
        self.save()

    def check_and_update(self, server_name: str, entity: Entity) -> tuple[bool, list[str]]:
        logger.debug("Checking entity: %s in server: %s", entity.name, server_name)
        entity_type = entity_type_to_str(entity)
        key = f"{server_name}.{entity_type}.{entity.name}"
        hash = hash_entity(entity)

        new_data = ScannedEntity(
            hash=hash,
            type=entity_type,
            timestamp=datetime.now(),
            description=entity.description,
        )
        changed = False
        messages = []
        prev_data = None
        if key in self.scanned_entities.root:
            prev_data = self.scanned_entities.root[key]
            changed = prev_data.hash != new_data.hash
            if changed:
                logger.info("Entity %s has changed since last scan", entity.name)
                logger.debug("Previous hash: %s, new hash: %s", prev_data.hash, new_data.hash)
                messages.append(
                    f"[bold]Previous description[/bold] ({prev_data.timestamp.strftime('%d/%m/%Y, %H:%M:%S')})"
                )
                messages.append(prev_data.description)
        else:
            logger.debug("Entity %s is new (not previously scanned)", entity.name)

        self.scanned_entities.root[key] = new_data
        return changed, messages

    def get_background_scan_path(self):
        return os.path.join(self.path, "background_scan.json")

    def get_mcp_server_log_path(self, pid: int, client_name: str | None = None):
        date = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        file = os.path.join(self.path, "mcp_server", f"{date}_{pid}_{client_name}.log")
        # create folder if it doesn't exist
        os.makedirs(os.path.dirname(file), exist_ok=True)
        # create file if it doesn't exist
        if not os.path.exists(file):
            with open(file, "w") as f:
                f.write("")
        return file

    def print_whitelist(self) -> None:
        logger.info("Printing whitelist with %d entries", len(self.whitelist))
        whitelist_keys = sorted(self.whitelist.keys())
        for key in whitelist_keys:
            if "." in key:
                entity_type, name = key.split(".", 1)
            else:
                entity_type, name = "tool", key
            logger.debug("Whitelist entry: %s - %s - %s", entity_type, name, self.whitelist[key])
            rich.print(entity_type, name, self.whitelist[key])
        rich.print(f"[bold]{len(whitelist_keys)} entries in whitelist[/bold]")

    def add_to_whitelist(self, entity_type: str, name: str, hash: str) -> None:
        key = f"{entity_type}.{name}"
        logger.info("Adding to whitelist: %s with hash: %s", key, hash)
        self.whitelist[key] = hash
        self.save()

    def is_whitelisted(self, entity: Entity) -> bool:
        hash = hash_entity(entity)
        result = hash in self.whitelist.values()
        logger.debug("Checking if entity %s is whitelisted: %s", entity.name, result)
        return result

    def save(self) -> None:
        logger.info("Saving storage data to %s", self.path)
        with self._lock:
            try:
                os.makedirs(self.path, exist_ok=True)
                scanned_entities_path = os.path.join(self.path, "scanned_entities.json")
                logger.debug("Saving scanned entities to: %s", scanned_entities_path)
                with open(scanned_entities_path, "w") as f:
                    f.write(self.scanned_entities.model_dump_json())

                whitelist_path = os.path.join(self.path, "whitelist.json")
                logger.debug("Saving whitelist to: %s", whitelist_path)
                with open(whitelist_path, "w") as f:
                    json.dump(self.whitelist, f)
                logger.info("Successfully saved storage files")
            except Exception as e:
                logger.exception("Error saving storage files: %s", e)

from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

from .database import ThreatDatabase, ThreatEntry
from .sources import ThreatSource, LocalFileSource, URLSource, OpenTIPSource, RawThreatData
from .scheduler import ThreatUpdateScheduler, ScheduleType


logger = logging.getLogger(__name__)


class ThreatIntelligenceManager:
    def __init__(
        self,
        storage_path: Optional[str] = None,
        auto_save: bool = True,
        update_interval: int = 3600
    ):
        self._database = ThreatDatabase(storage_path)
        self._sources: Dict[str, ThreatSource] = {}
        self._scheduler: Optional[ThreatUpdateScheduler] = None
        self._auto_save = auto_save
        self._update_interval = update_interval
        self._firewall_integration: Optional[Any] = None

    def add_source(self, source: ThreatSource) -> None:
        self._sources[source.name] = source

    def add_local_file_source(self, file_path: str, name: Optional[str] = None) -> LocalFileSource:
        source_name = name or f"local_{hash(file_path) % 10000}"
        source = LocalFileSource(file_path, source_name)
        self.add_source(source)
        return source

    def add_url_source(self, url: str, name: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> URLSource:
        source_name = name or f"url_{hash(url) % 10000}"
        source = URLSource(url, source_name, headers)
        self.add_source(source)
        return source

    def add_opentip_source(self, api_url: Optional[str] = None, api_key: Optional[str] = None) -> OpenTIPSource:
        source = OpenTIPSource(api_url or "https://api.opentip.org", api_key)
        self.add_source(source)
        return source

    def remove_source(self, name: str) -> bool:
        if name in self._sources:
            del self._sources[name]
            return True
        return False

    def get_source(self, name: str) -> Optional[ThreatSource]:
        return self._sources.get(name)

    def get_sources(self) -> Dict[str, ThreatSource]:
        return self._sources.copy()

    def update_from_source(self, source_name: str, merge: bool = True) -> int:
        source = self._sources.get(source_name)
        if not source:
            raise ValueError(f"Source not found: {source_name}")

        raw_threats = source.fetch()
        
        if not merge:
            self._database.clear()
        
        count = 0
        for raw in raw_threats:
            self._database.add_threat(
                pattern=raw.pattern,
                severity=raw.severity,
                category=raw.category,
                description=raw.description,
                source=raw.source
            )
            count += 1

        if self._auto_save:
            self._database.save()

        self._sync_to_firewall()

        logger.info(f"Updated {count} threats from source: {source_name}")
        return count

    def update_from_all_sources(self, merge: bool = True) -> Dict[str, int]:
        results = {}
        
        for name, source in self._sources.items():
            try:
                count = self.update_from_source(name, merge=merge)
                results[name] = count
            except Exception as e:
                logger.error(f"Failed to update from source {name}: {e}")
                results[name] = 0

        return results

    def _update_callback(self) -> int:
        results = self.update_from_all_sources(merge=True)
        return sum(results.values())

    def start_auto_update(
        self,
        interval_seconds: Optional[int] = None,
        schedule_type: ScheduleType = ScheduleType.INTERVAL
    ) -> None:
        if interval_seconds:
            self._update_interval = interval_seconds

        self._scheduler = ThreatUpdateScheduler(
            update_callback=self._update_callback,
            interval_seconds=self._update_interval,
            schedule_type=schedule_type
        )
        self._scheduler.start()
        logger.info(f"Started auto-update with interval: {self._update_interval}s")

    def stop_auto_update(self) -> None:
        if self._scheduler:
            self._scheduler.stop()
            self._scheduler = None
            logger.info("Stopped auto-update")

    def update_now(self) -> Dict[str, Any]:
        if not self._scheduler:
            return {"error": "Scheduler not running"}
        
        return self._scheduler.update_now()

    def set_update_interval(self, seconds: int) -> None:
        self._update_interval = seconds
        if self._scheduler:
            self._scheduler.set_interval(seconds)

    def get_threats(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[ThreatEntry]:
        return self._database.get_threats(category=category, severity=severity)

    def search_threats(self, query: str) -> List[ThreatEntry]:
        return self._database.search(query)

    def get_threat(self, threat_id: str) -> Optional[ThreatEntry]:
        return self._database.get_threat(threat_id)

    def add_threat(
        self,
        pattern: str,
        severity: str,
        category: str,
        description: str,
        source: str = "manual"
    ) -> ThreatEntry:
        entry = self._database.add_threat(
            pattern=pattern,
            severity=severity,
            category=category,
            description=description,
            source=source
        )
        
        if self._auto_save:
            self._database.save()
        
        self._sync_to_firewall()
        
        return entry

    def remove_threat(self, threat_id: str) -> bool:
        result = self._database.remove_threat(threat_id)
        
        if result and self._auto_save:
            self._database.save()
        
        return result

    def export_database(self, file_path: str) -> None:
        self._database.export(file_path)

    def import_database(self, file_path: str, merge: bool = True) -> int:
        count = self._database.import_data(file_path, merge=merge)
        
        if self._auto_save:
            self._database.save()
        
        self._sync_to_firewall()
        
        return count

    def clear_database(self) -> None:
        self._database.clear()
        
        if self._auto_save:
            self._database.save()
        
        self._sync_to_firewall()

    def check_pattern(self, pattern: str) -> Optional[ThreatEntry]:
        matches = self._database.search(pattern)
        return matches[0] if matches else None

    def check_patterns(self, patterns: List[str]) -> Dict[str, Optional[ThreatEntry]]:
        results = {}
        for pattern in patterns:
            results[pattern] = self.check_pattern(pattern)
        return results

    def integrate_firewall(self, firewall) -> None:
        self._firewall_integration = firewall
        self._sync_to_firewall()

    def _sync_to_firewall(self) -> None:
        if not self._firewall_integration:
            return

        try:
            threats = self._database.get_threats()
            patterns = [(t.pattern, t.severity, t.category) for t in threats]
            
            if hasattr(self._firewall_integration, "update_threat_patterns"):
                self._firewall_integration.update_threat_patterns(patterns)
            elif hasattr(self._firewall_integration, "set_threat_patterns"):
                self._firewall_integration.set_threat_patterns(patterns)
            
            logger.info(f"Synced {len(patterns)} threat patterns to firewall")
        except Exception as e:
            logger.error(f"Failed to sync to firewall: {e}")

    def get_stats(self) -> Dict[str, Any]:
        db_stats = self._database.get_stats()
        
        sources_info = {}
        for name, source in self._sources.items():
            sources_info[name] = {
                "type": source.get_source_type(),
                "last_update": source.last_update.isoformat() if source.last_update else None
            }

        scheduler_info = None
        if self._scheduler:
            scheduler_info = self._scheduler.get_status()

        return {
            "database": db_stats,
            "sources": sources_info,
            "scheduler": scheduler_info,
            "firewall_integrated": self._firewall_integration is not None
        }

    @property
    def database(self) -> ThreatDatabase:
        return self._database

    @property
    def scheduler(self) -> Optional[ThreatUpdateScheduler]:
        return self._scheduler

    @property
    def is_auto_update_running(self) -> bool:
        return self._scheduler is not None and self._scheduler.is_running()

    def __len__(self) -> int:
        return len(self._database)

    def __contains__(self, threat_id: str) -> bool:
        return threat_id in self._database

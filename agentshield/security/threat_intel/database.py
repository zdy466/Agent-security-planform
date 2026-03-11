import json
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any


@dataclass
class ThreatEntry:
    id: str
    pattern: str
    severity: str
    category: str
    description: str
    source: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatEntry":
        return cls(**data)


class ThreatDatabase:
    def __init__(self, storage_path: Optional[str] = None):
        self._threats: Dict[str, ThreatEntry] = {}
        self._storage_path = storage_path
        if storage_path and Path(storage_path).exists():
            self.load()

    def add_threat(
        self,
        pattern: str,
        severity: str,
        category: str,
        description: str,
        source: str,
        id: Optional[str] = None
    ) -> ThreatEntry:
        threat_id = id or str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        
        entry = ThreatEntry(
            id=threat_id,
            pattern=pattern,
            severity=severity,
            category=category,
            description=description,
            source=source,
            created_at=created_at
        )
        
        self._threats[threat_id] = entry
        return entry

    def remove_threat(self, threat_id: str) -> bool:
        if threat_id in self._threats:
            del self._threats[threat_id]
            return True
        return False

    def get_threat(self, threat_id: str) -> Optional[ThreatEntry]:
        return self._threats.get(threat_id)

    def get_threats(self, category: Optional[str] = None, severity: Optional[str] = None) -> List[ThreatEntry]:
        results = list(self._threats.values())
        
        if category:
            results = [t for t in results if t.category == category]
        if severity:
            results = [t for t in results if t.severity == severity]
        
        return results

    def search(self, query: str) -> List[ThreatEntry]:
        query_lower = query.lower()
        results = []
        
        for threat in self._threats.values():
            if (query_lower in threat.pattern.lower() or
                query_lower in threat.description.lower() or
                query_lower in threat.category.lower() or
                query_lower in threat.source.lower()):
                results.append(threat)
        
        return results

    def clear(self) -> None:
        self._threats.clear()

    def export(self, file_path: str) -> None:
        data = {
            "exported_at": datetime.now().isoformat(),
            "threats": [threat.to_dict() for threat in self._threats.values()]
        }
        
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def import_data(self, file_path: str, merge: bool = True) -> int:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        if not merge:
            self.clear()
        
        count = 0
        for threat_data in data.get("threats", []):
            threat = ThreatEntry.from_dict(threat_data)
            self._threats[threat.id] = threat
            count += 1
        
        return count

    def load(self) -> None:
        if not self._storage_path:
            return
        
        path = Path(self._storage_path)
        if not path.exists():
            return
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for threat_data in data.get("threats", []):
                threat = ThreatEntry.from_dict(threat_data)
                self._threats[threat.id] = threat
        except (json.JSONDecodeError, KeyError):
            pass

    def save(self) -> None:
        if not self._storage_path:
            return
        
        self.export(self._storage_path)

    def get_stats(self) -> Dict[str, Any]:
        categories = {}
        severities = {}
        
        for threat in self._threats.values():
            categories[threat.category] = categories.get(threat.category, 0) + 1
            severities[threat.severity] = severities.get(threat.severity, 0) + 1
        
        return {
            "total_threats": len(self._threats),
            "categories": categories,
            "severities": severities
        }

    def __len__(self) -> int:
        return len(self._threats)

    def __contains__(self, threat_id: str) -> bool:
        return threat_id in self._threats

    def __iter__(self):
        return iter(self._threats.values())

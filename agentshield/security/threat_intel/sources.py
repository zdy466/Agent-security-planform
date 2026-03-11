import json
import csv
import io
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


@dataclass
class RawThreatData:
    pattern: str
    severity: str
    category: str
    description: str
    source: str


class ThreatSource(ABC):
    def __init__(self, name: str):
        self.name = name
        self._last_update: Optional[datetime] = None
        self._last_hash: Optional[str] = None

    @abstractmethod
    def fetch(self) -> List[RawThreatData]:
        pass

    @abstractmethod
    def get_source_type(self) -> str:
        pass

    def has_changed(self, content: bytes) -> bool:
        content_hash = hashlib.md5(content).hexdigest()
        if self._last_hash is None:
            self._last_hash = content_hash
            return True
        if content_hash != self._last_hash:
            self._last_hash = content_hash
            return True
        return False

    def update_timestamp(self) -> None:
        self._last_update = datetime.now()

    @property
    def last_update(self) -> Optional[datetime]:
        return self._last_update


class LocalFileSource(ThreatSource):
    def __init__(self, file_path: str, name: str = "local_file"):
        super().__init__(name)
        self.file_path = Path(file_path)
        self._file_format = self._detect_format()

    def _detect_format(self) -> str:
        suffix = self.file_path.suffix.lower()
        if suffix == ".json":
            return "json"
        elif suffix in [".csv", ".txt"]:
            return "csv"
        elif suffix in [".stix", ".stix2"]:
            return "stix"
        return "unknown"

    def get_source_type(self) -> str:
        return f"local_file:{self._file_format}"

    def fetch(self) -> List[RawThreatData]:
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")

        with open(self.file_path, "r", encoding="utf-8") as f:
            content = f.read().encode("utf-8")

        if not self.has_changed(content):
            return []

        self.update_timestamp()

        if self._file_format == "json":
            return self._parse_json(f)
        elif self._file_format == "csv":
            return self._parse_csv(f)
        else:
            return []

    def _parse_json(self, file_obj: io.TextIOWrapper) -> List[RawThreatData]:
        threats = []
        try:
            data = json.load(file_obj)
            items = data if isinstance(data, list) else data.get("threats", [])
            
            for item in items:
                threats.append(RawThreatData(
                    pattern=item.get("pattern", ""),
                    severity=item.get("severity", "medium"),
                    category=item.get("category", "unknown"),
                    description=item.get("description", ""),
                    source=self.name
                ))
        except json.JSONDecodeError:
            pass
        
        return threats

    def _parse_csv(self, file_obj: io.TextIOWrapper) -> List[RawThreatData]:
        threats = []
        reader = csv.DictReader(file_obj)
        
        for row in reader:
            threats.append(RawThreatData(
                pattern=row.get("pattern", ""),
                severity=row.get("severity", "medium"),
                category=row.get("category", "unknown"),
                description=row.get("description", ""),
                source=self.name
            ))
        
        return threats


class URLSource(ThreatSource):
    def __init__(self, url: str, name: str = "url", headers: Optional[Dict[str, str]] = None):
        super().__init__(name)
        self.url = url
        self.headers = headers or {"User-Agent": "ThreatIntelClient/1.0"}
        self._timeout = 30

    def get_source_type(self) -> str:
        return "url"

    def fetch(self) -> List[RawThreatData]:
        try:
            request = Request(self.url, headers=self.headers)
            with urlopen(request, timeout=self._timeout) as response:
                content = response.read()

            if not self.has_changed(content):
                return []

            self.update_timestamp()

            return self._parse_content(content, response.headers.get("Content-Type", ""))

        except (HTTPError, URLError) as e:
            raise RuntimeError(f"Failed to fetch from {self.url}: {str(e)}")

    def _parse_content(self, content: bytes, content_type: str) -> List[RawThreatData]:
        if "application/json" in content_type:
            return self._parse_json(content)
        elif "text/csv" in content_type:
            return self._parse_csv(content)
        elif "text/plain" in content_type:
            return self._parse_text(content)
        
        try:
            return self._parse_json(content)
        except:
            return self._parse_text(content)

    def _parse_json(self, content: bytes) -> List[RawThreatData]:
        threats = []
        data = json.loads(content.decode("utf-8"))
        
        items = data if isinstance(data, list) else data.get("threats", data.get("data", []))
        
        for item in items:
            if isinstance(item, dict):
                threats.append(RawThreatData(
                    pattern=item.get("pattern", item.get("indicator", "")),
                    severity=item.get("severity", "medium"),
                    category=item.get("category", item.get("type", "unknown")),
                    description=item.get("description", ""),
                    source=self.name
                ))
        
        return threats

    def _parse_csv(self, content: bytes) -> List[RawThreatData]:
        threats = []
        reader = csv.DictReader(io.TextIOWrapper(content, encoding="utf-8"))
        
        for row in reader:
            threats.append(RawThreatData(
                pattern=row.get("pattern", row.get("indicator", "")),
                severity=row.get("severity", "medium"),
                category=row.get("category", "unknown"),
                description=row.get("description", ""),
                source=self.name
            ))
        
        return threats

    def _parse_text(self, content: bytes) -> List[RawThreatData]:
        threats = []
        text = content.decode("utf-8")
        
        for line in text.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                threats.append(RawThreatData(
                    pattern=line,
                    severity="medium",
                    category="unknown",
                    description="",
                    source=self.name
                ))
        
        return threats


class OpenTIPSource(ThreatSource):
    def __init__(
        self,
        api_url: str = "https://api.opentip.org",
        api_key: Optional[str] = None,
        name: str = "opentip"
    ):
        super().__init__(name)
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self._timeout = 30

    def get_source_type(self) -> str:
        return "opentip"

    def fetch(self) -> List[RawThreatData]:
        if not self.api_key:
            return self._fetch_public()
        
        return self._fetch_with_auth()

    def _fetch_public(self) -> List[RawThreatData]:
        endpoints = [
            f"{self.api_url}/feeds/latest",
            f"{self.api_url}/threats/latest"
        ]
        
        for endpoint in endpoints:
            try:
                request = Request(endpoint, headers={"User-Agent": "ThreatIntelClient/1.0"})
                with urlopen(request, timeout=self._timeout) as response:
                    content = response.read()

                if self.has_changed(content):
                    self.update_timestamp()
                    return self._parse_response(content)
            except (HTTPError, URLError):
                continue
        
        return []

    def _fetch_with_auth(self) -> List[RawThreatData]:
        try:
            headers = {
                "User-Agent": "ThreatIntelClient/1.0",
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            endpoints = [
                f"{self.api_url}/v1/threats",
                f"{self.api_url}/v1/indicators"
            ]
            
            for endpoint in endpoints:
                request = Request(endpoint, headers=headers)
                with urlopen(request, timeout=self._timeout) as response:
                    content = response.read()

                if self.has_changed(content):
                    self.update_timestamp()
                    return self._parse_response(content)
        
        except (HTTPError, URLError) as e:
            raise RuntimeError(f"Failed to fetch from OpenTIP: {str(e)}")
        
        return []

    def _parse_response(self, content: bytes) -> List[RawThreatData]:
        threats = []
        
        try:
            data = json.loads(content.decode("utf-8"))
        except json.JSONDecodeError:
            return threats

        items = data if isinstance(data, list) else data.get("data", data.get("threats", []))

        for item in items:
            if isinstance(item, dict):
                threats.append(RawThreatData(
                    pattern=item.get("indicator", item.get("pattern", "")),
                    severity=self._normalize_severity(item.get("severity", "medium")),
                    category=self._normalize_category(item.get("type", item.get("category", "unknown"))),
                    description=item.get("description", ""),
                    source=self.name
                ))

        return threats

    def _normalize_severity(self, severity: str) -> str:
        severity_lower = severity.lower()
        if severity_lower in ["critical", "high"]:
            return "high"
        elif severity_lower in ["medium", "moderate"]:
            return "medium"
        return "low"

    def _normalize_category(self, category: str) -> str:
        category_lower = category.lower()
        if "malware" in category_lower:
            return "malware"
        elif "phishing" in category_lower:
            return "phishing"
        elif "c2" in category_lower or "command" in category_lower:
            return "c2"
        elif "ip" in category_lower:
            return "ip"
        elif "domain" in category_lower:
            return "domain"
        elif "url" in category_lower:
            return "url"
        elif "file" in category_lower or "hash" in category_lower:
            return "file_hash"
        return "unknown"

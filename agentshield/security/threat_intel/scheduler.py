import threading
import time
from datetime import datetime
from typing import Callable, Optional, Dict, Any
from enum import Enum


class ScheduleType(Enum):
    INTERVAL = "interval"
    DAILY = "daily"
    HOURLY = "hourly"


class ThreatUpdateScheduler:
    def __init__(
        self,
        update_callback: Callable[[], int],
        interval_seconds: int = 3600,
        schedule_type: ScheduleType = ScheduleType.INTERVAL
    ):
        self._callback = update_callback
        self._interval = interval_seconds
        self._schedule_type = schedule_type
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_run: Optional[datetime] = None
        self._next_run: Optional[datetime] = None
        self._last_result: Optional[Dict[str, Any]] = None
        self._error: Optional[str] = None

    def start(self) -> None:
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        
        self._running = False
        self._stop_event.set()
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run_loop(self) -> None:
        while self._running and not self._stop_event.is_set():
            try:
                self._execute_update()
            except Exception as e:
                self._error = str(e)
            
            self._calculate_next_run()
            
            if self._running and not self._stop_event.is_set():
                self._stop_event.wait(timeout=self._interval)

    def _execute_update(self) -> None:
        try:
            count = self._callback()
            self._last_result = {
                "success": True,
                "threats_updated": count,
                "timestamp": datetime.now().isoformat()
            }
            self._error = None
        except Exception as e:
            self._last_result = {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
            self._error = str(e)
            raise
        
        self._last_run = datetime.now()

    def _calculate_next_run(self) -> None:
        if self._schedule_type == ScheduleType.INTERVAL:
            self._next_run = datetime.now()
        elif self._schedule_type == ScheduleType.HOURLY:
            now = datetime.now()
            self._next_run = now.replace(minute=0, second=0, microsecond=0)
            if now.minute > 0:
                from datetime import timedelta
                self._next_run = self._next_run + timedelta(hours=1)
        elif self._schedule_type == ScheduleType.DAILY:
            now = datetime.now()
            self._next_run = now.replace(hour=0, minute=0, second=0, microsecond=0)
            from datetime import timedelta
            self._next_run = self._next_run + timedelta(days=1)

    def update_now(self) -> Dict[str, Any]:
        self._execute_update()
        return self._last_result or {}

    def set_interval(self, seconds: int) -> None:
        if seconds <= 0:
            raise ValueError("Interval must be positive")
        self._interval = seconds

    def get_interval(self) -> int:
        return self._interval

    def set_schedule_type(self, schedule_type: ScheduleType) -> None:
        self._schedule_type = schedule_type

    def get_schedule_type(self) -> ScheduleType:
        return self._schedule_type

    def is_running(self) -> bool:
        return self._running

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    @property
    def next_run(self) -> Optional[datetime]:
        return self._next_run

    @property
    def last_result(self) -> Optional[Dict[str, Any]]:
        return self._last_result

    @property
    def error(self) -> Optional[str]:
        return self._error

    def get_status(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "schedule_type": self._schedule_type.value,
            "interval_seconds": self._interval,
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "next_run": self._next_run.isoformat() if self._next_run else None,
            "last_result": self._last_result,
            "error": self._error
        }

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

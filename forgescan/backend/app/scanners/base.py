# backend/app/scanners/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import asyncio


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanResult:
    status: ScanStatus
    findings: List[Dict[str, Any]]
    summary: Dict[str, Any]
    metadata: Dict[str, Any]
    error: Optional[str] = None


class BaseScannerPlugin(ABC):
    """Abstract base class for all scanner plugins"""
    
    name: str
    version: str
    description: str
    supported_protocols: List[str]
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize scanner plugin"""
        pass
    
    @abstractmethod
    async def scan(
        self,
        target: str,
        scan_id: str,
        tenant_id: str,
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Execute scan on target"""
        pass
    
    @abstractmethod
    async def validate_target(self, target: str) -> bool:
        """Validate if target is scannable by this plugin"""
        pass
    
    async def cleanup(self) -> None:
        """Cleanup resources after scan"""
        pass


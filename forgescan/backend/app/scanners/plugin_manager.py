# backend/app/scanners/plugin_manager.py
import importlib
from typing import Dict, Optional
from pathlib import Path

from app.scanners.base import BaseScannerPlugin
from app.scanners.web_scanner import WebScanner
from app.scanners.api_scanner import APIScanner
from app.scanners.sca_scanner import SCAScanner
from app.core.logging import logger


class PluginManager:
    """Manager for scanner plugins"""
    
    def __init__(self):
        self._plugins: Dict[str, BaseScannerPlugin] = {}
        self._initialized = False
    
    async def initialize(self) -> None:
        """Discover and initialize all plugins"""
        if self._initialized:
            return
        
        logger.info("Initializing scanner plugins")
        
        # Register built-in scanners
        scanners = [
            WebScanner(),
            APIScanner(),
        ]
        
        # Initialize each scanner
        for scanner in scanners:
            await scanner.initialize()
            self._plugins[scanner.name] = scanner
            logger.info(f"Registered scanner: {scanner.name} v{scanner.version}")
        
        self._initialized = True
    
    async def get_scanner(
        self, 
        scanner_type: str,
        target: Optional[str] = None
    ) -> Optional[BaseScannerPlugin]:
        """Get appropriate scanner for target"""
        scanner_name = f"{scanner_type}_scanner"
        
        if scanner_name in self._plugins:
            plugin = self._plugins[scanner_name]
            if target and not await plugin.validate_target(target):
                return None
            return plugin
        
        return None
    
    async def cleanup_all(self) -> None:
        """Cleanup all plugins"""
        for plugin in self._plugins.values():
            await plugin.cleanup()


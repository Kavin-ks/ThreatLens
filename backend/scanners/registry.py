"""
ScannerRegistry — discovers, registers, and looks up scanner instances.

Scanners self-register by applying the @scanner_registry.register decorator.
The registry is a singleton; import it as:

    from scanners.registry import scanner_registry
"""
import importlib
import pkgutil
import logging
from typing import Dict, List, Optional, Type, TYPE_CHECKING

if TYPE_CHECKING:
    from scanners.base import BaseScanner
    from scanners.models import ScanTarget, SecurityCategory, StackType

logger = logging.getLogger(__name__)


class ScannerRegistry:
    def __init__(self):
        self._scanners: Dict[str, "BaseScanner"] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, cls: Type["BaseScanner"]) -> Type["BaseScanner"]:
        """
        Class decorator that registers a scanner class.

            @scanner_registry.register
            class MyScannerClass(BaseScanner):
                ...
        """
        required = ("scanner_id", "name", "description", "category")
        for attr in required:
            if not hasattr(cls, attr):
                raise TypeError(
                    f"Scanner {cls.__name__!r} is missing required class attribute {attr!r}"
                )
        instance = cls()
        sid = cls.scanner_id
        if sid in self._scanners:
            logger.warning("Scanner %r already registered — overwriting", sid)
        self._scanners[sid] = instance
        logger.debug("Registered scanner: %s", sid)
        return cls

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, scanner_id: str) -> Optional["BaseScanner"]:
        return self._scanners.get(scanner_id)

    def all(self) -> List["BaseScanner"]:
        return list(self._scanners.values())

    def by_ids(self, scanner_ids: List[str]) -> List["BaseScanner"]:
        return [self._scanners[sid] for sid in scanner_ids if sid in self._scanners]

    def for_target(self, target: "ScanTarget") -> List["BaseScanner"]:
        """Return all scanners that report can_scan(target) == True."""
        applicable = []
        for scanner in self._scanners.values():
            try:
                if scanner.can_scan(target):
                    applicable.append(scanner)
            except Exception as exc:
                logger.warning("can_scan() raised for %s: %s", scanner.scanner_id, exc)
        return applicable

    def summary(self) -> List[dict]:
        return [
            {
                "scanner_id": s.scanner_id,
                "name": s.name,
                "description": s.description,
                "category": s.category,
                "requires_running_app": s.requires_running_app,
            }
            for s in self._scanners.values()
        ]

    # ------------------------------------------------------------------
    # Auto-discovery
    # ------------------------------------------------------------------

    def autodiscover(self, package_name: str = "scanners") -> int:
        """
        Walk all sub-packages under `package_name` and import every module.
        Any module that uses @scanner_registry.register will self-register on import.
        Returns the number of newly registered scanners.
        """
        before = len(self._scanners)
        try:
            package = importlib.import_module(package_name)
            package_path = package.__path__

            for _, module_name, is_pkg in pkgutil.walk_packages(
                package_path, prefix=package_name + "."
            ):
                try:
                    importlib.import_module(module_name)
                except Exception as exc:
                    logger.warning("Failed to import scanner module %s: %s", module_name, exc)
        except ImportError as exc:
            logger.error("Cannot autodiscover scanners in %s: %s", package_name, exc)

        added = len(self._scanners) - before
        logger.info("Scanner autodiscovery complete: %d scanner(s) registered", len(self._scanners))
        return added

    def __len__(self) -> int:
        return len(self._scanners)

    def __repr__(self) -> str:
        return f"<ScannerRegistry scanners={list(self._scanners.keys())!r}>"


# Module-level singleton
scanner_registry = ScannerRegistry()

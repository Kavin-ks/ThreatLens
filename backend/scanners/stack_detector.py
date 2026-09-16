"""
StackDetector — identifies the technology stack of a scan target.

Examines file extensions, package manifests, framework signatures, and
directory structure to produce a StackProfile that the ScanOrchestrator
uses to select relevant scanners.
"""
import json
import logging
from pathlib import Path
from typing import Optional

from scanners.models import StackProfile, StackType

logger = logging.getLogger(__name__)

# Manifest files → package managers / languages
_MANIFEST_SIGNALS = {
    "package.json": (StackType.NODEJS, "npm"),
    "yarn.lock": (StackType.NODEJS, "yarn"),
    "pnpm-lock.yaml": (StackType.NODEJS, "pnpm"),
    "requirements.txt": (StackType.PYTHON, "pip"),
    "Pipfile": (StackType.PYTHON, "pipenv"),
    "pyproject.toml": (StackType.PYTHON, "pip"),
    "setup.py": (StackType.PYTHON, "pip"),
    "pom.xml": (StackType.JAVA, "maven"),
    "build.gradle": (StackType.JAVA, "gradle"),
    "go.mod": (StackType.GO, "go"),
    "Gemfile": (StackType.RUBY, "bundler"),
    "composer.json": (StackType.PHP, "composer"),
    "*.csproj": (StackType.DOTNET, "dotnet"),
    "Cargo.toml": (StackType.RUST, "cargo"),
}

# File extensions → languages
_EXTENSION_SIGNALS = {
    ".py": StackType.PYTHON,
    ".js": StackType.JAVASCRIPT,
    ".ts": StackType.TYPESCRIPT,
    ".jsx": StackType.JAVASCRIPT,
    ".tsx": StackType.TYPESCRIPT,
    ".java": StackType.JAVA,
    ".go": StackType.GO,
    ".rb": StackType.RUBY,
    ".php": StackType.PHP,
    ".cs": StackType.DOTNET,
    ".rs": StackType.RUST,
}

# Framework signatures: file/dir presence → framework name
_FRAMEWORK_SIGNALS = {
    "manage.py": "Django",
    "flask_app.py": "Flask",
    "wsgi.py": "WSGI",
    "asgi.py": "ASGI",
    "next.config.js": "Next.js",
    "next.config.ts": "Next.js",
    "nuxt.config.js": "Nuxt.js",
    "angular.json": "Angular",
    "vue.config.js": "Vue.js",
    "svelte.config.js": "Svelte",
    "vite.config.ts": "Vite",
    "vite.config.js": "Vite",
}

# Directories suggesting API or frontend presence
_API_DIRS = {"routes", "controllers", "api", "endpoints", "views"}
_FRONTEND_DIRS = {"frontend", "client", "web", "static", "public", "src/components"}


class StackDetector:
    """Detect the technology stack of a scan target directory."""

    def detect(self, target_path: Path) -> StackProfile:
        if not target_path or not target_path.exists():
            return StackProfile()

        languages: set = set()
        package_managers: set = set()
        frameworks: set = set()
        indicators: dict = {}

        root_files = {f.name for f in target_path.iterdir() if f.is_file()}
        root_dirs = {d.name for d in target_path.iterdir() if d.is_dir()}

        # Manifest file detection
        for manifest, (lang, pm) in _MANIFEST_SIGNALS.items():
            if manifest.startswith("*"):
                # Glob pattern
                ext = manifest[1:]
                if any(f.endswith(ext) for f in root_files):
                    languages.add(lang)
                    package_managers.add(pm)
                    indicators[f"glob:{manifest}"] = True
            elif manifest in root_files:
                languages.add(lang)
                package_managers.add(pm)
                indicators[f"manifest:{manifest}"] = True

        # Framework signals
        for signal, framework in _FRAMEWORK_SIGNALS.items():
            if signal in root_files:
                frameworks.add(framework)
                indicators[f"framework:{signal}"] = True

        # Extension-based language detection (sample first 200 files max)
        ext_counts: dict = {}
        try:
            for p in list(target_path.rglob("*"))[:500]:
                if p.is_file() and not any(
                    part.startswith(".") or part in ("node_modules", "__pycache__", ".venv", "venv")
                    for part in p.parts
                ):
                    ext = p.suffix.lower()
                    if ext in _EXTENSION_SIGNALS:
                        ext_counts[ext] = ext_counts.get(ext, 0) + 1
        except OSError:
            pass

        for ext, count in ext_counts.items():
            if count >= 1:
                languages.add(_EXTENSION_SIGNALS[ext])
                indicators[f"ext:{ext}"] = count

        # Django: check package.json for framework info
        if "package.json" in root_files:
            try:
                pkg = json.loads((target_path / "package.json").read_text())
                deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                for fw_key, fw_name in [("react", "React"), ("vue", "Vue.js"), ("angular", "@angular/core"), ("express", "Express"), ("fastify", "Fastify"), ("nestjs", "NestJS")]:
                    if fw_key in deps or f"@angular/core" in deps:
                        frameworks.add(fw_name)
            except (OSError, json.JSONDecodeError):
                pass

        has_api = bool(root_dirs & _API_DIRS) or any(d in frameworks for d in ["Express", "FastAPI", "Django", "Flask", "NestJS"])
        has_frontend = bool(root_dirs & {"frontend", "client", "web"}) or any(f in frameworks for f in ["React", "Vue.js", "Angular", "Next.js"])

        profile = StackProfile(
            languages=sorted(languages, key=lambda x: x.value),
            frameworks=sorted(frameworks),
            package_managers=sorted(package_managers),
            has_api=has_api,
            has_frontend=has_frontend,
            raw_indicators=indicators,
        )
        logger.info(
            "Stack detection complete: languages=%s frameworks=%s",
            [l.value for l in profile.languages],
            profile.frameworks,
        )
        return profile

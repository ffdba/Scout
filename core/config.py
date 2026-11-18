from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

try:
    from dotenv import load_dotenv
    _DOTENV_AVAILABLE = True
except ImportError:
    def load_dotenv(*args, **kwargs):
        pass
    _DOTENV_AVAILABLE = False

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yaml"
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


class Config:
    def __init__(self, config_path: str | None = None):
        self._data: dict[str, Any] = {}
        self._load(config_path)

    def _load(self, config_path: str | None = None):
        load_dotenv(_ENV_PATH)

        path = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
        if not path.exists():
            example_path = path.parent / "config.example.yaml"
            if example_path.exists():
                path = example_path
            else:
                self._data = self._defaults()
                self._apply_env_overrides()
                return

        with open(path, "r", encoding="utf-8") as f:
            self._data = yaml.safe_load(f) or {}

        self._apply_env_overrides()

    def _apply_env_overrides(self):
        env_map = {
            "AI_API_KEY": ("ai", "api_key"),
            "AI_BASE_URL": ("ai", "base_url"),
            "AI_MODEL": ("ai", "model"),
            "QUAKE_API_KEY": ("quake", "api_key"),
            "HUNTER_API_KEY": ("hunter", "api_key"),
            "HTTP_PROXY": ("proxy", "http"),
            "HTTPS_PROXY": ("proxy", "https"),
        }
        for env_var, keys in env_map.items():
            val = os.environ.get(env_var, "").strip()
            if val:
                section = self._data.setdefault(keys[0], {})
                section[keys[1]] = val

    @staticmethod
    def _defaults() -> dict[str, Any]:
        return {
            "ai": {"provider": "openai", "api_key": "", "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4o", "temperature": 0.2, "max_tokens": 4096},
            "quake": {"api_key": ""},
            "hunter": {"api_key": ""},
            "crtsh": {"timeout": 30},
            "gitleaks": {"repo_path": ""},
            "subfinder": {"config_path": "", "timeout": 300, "threads": 10},
            "portscan": {"engine": "rustscan", "rustscan": {"timeout": 300, "batch_size": 512, "ulimit": 5000},
                         "naabu": {"timeout": 300, "rate": 1000, "top_ports": 1000}},
            "nmap": {"timeout": 600, "service_detection": True, "os_detection": False, "scripts": "default,vuln"},
            "httpx": {"timeout": 30, "threads": 25, "follow_redirects": True, "status_codes": True, "tech_detect": True},
            "wappalyzer": {"timeout": 30},
            "katana": {"timeout": 300, "depth": 3, "threads": 10, "js_crawl": True, "autofill": True},
            "feroxbuster": {"timeout": 300, "threads": 50,
                            "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                            "status_codes": "200,204,301,302,307,401,403",
                            "extensions": "php,asp,aspx,jsp,html,js,bak,old,zip,tar.gz,sql,conf,env,yml,yaml,json,xml"},
            "nuclei": {"timeout": 600, "templates": "", "severity": "low,medium,high,critical",
                       "tags": "", "rate_limit": 150},
            "output": {"dir": "./output", "format": "jsonl", "verbose": True},
            "proxy": {"enabled": False, "http": "", "https": ""},
        }

    def get(self, *keys: str, default: Any = None) -> Any:
        node = self._data
        for k in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(k, default)
            if node is None:
                return default
        return node

    def require(self, *keys: str) -> Any:
        val = self.get(*keys)
        if val is None or (isinstance(val, str) and not val.strip()):
            raise ValueError(f"配置项 {'.'.join(keys)} 未设置，请在 config/config.yaml 或 .env 中配置")
        return val

    @property
    def raw(self) -> dict[str, Any]:
        return self._data

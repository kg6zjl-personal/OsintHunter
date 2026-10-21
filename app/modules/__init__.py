from .base import REGISTRY, Module, Skip, register
from . import username, email, phone, domain, ip, web, misc, enrich, deep, documents, people, websearch, chile, chile_data  # noqa: F401,E402  (registran módulos)

__all__ = ["REGISTRY", "Module", "Skip", "register"]

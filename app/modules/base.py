from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..engine import Context


class Skip(Exception):
    """El módulo no se puede ejecutar (falta una clave, la entrada no aplica, etc.)."""


class Module:
    name: str = ""
    title: str = ""
    description: str = ""
    inputs: tuple[str, ...] = ()
    # claves obligatorias; si falta alguna el módulo se marca como omitido
    keys: tuple[str, ...] = ()
    # claves que mejoran el resultado pero no son necesarias
    optional_keys: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    timeout: float = 60
    # Enriquecedor: se ejecuta solo sobre cada entidad nueva que encaje, aunque no se pivote sobre ella.
    auto: bool = False
    # Búsqueda a fondo: nunca entra en la investigación normal ni en el pivotado; sólo se lanza a petición.
    deep: bool = False

    def applies(self, entity: dict) -> bool:
        return entity["type"] in self.inputs

    async def run(self, ctx: "Context") -> None:
        raise NotImplementedError

    def meta(self) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputs": list(self.inputs),
            "keys": list(self.keys),
            "optional_keys": list(self.optional_keys),
            "sources": list(self.sources),
            "deep": self.deep,
        }


REGISTRY: dict[str, Module] = {}


def register(cls):
    inst = cls()
    REGISTRY[inst.name] = inst
    return cls

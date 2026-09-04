"""TI Recon — external Threat Intelligence enrichment and analysis platform.

This package is the core TI engine. It is deliberately independent of Claude,
MCP and any LLM: those layers sit above it and are separate components.

Current scope is the Tasks 1-5 foundation — data model, credential
abstractions and the provider integration framework. No real provider
integration, planner, fusion or verdict engine exists yet.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"

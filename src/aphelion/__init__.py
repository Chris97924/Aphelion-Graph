"""Aphelion reference implementation - deterministic package format."""

__version__ = "0.5.1"
# Spec version is tracked independently from the package version: the
# on-disk Aphelion format may freeze at a MAJOR while the reference CLI
# ships additional 0.x releases. ``aphelion --version`` surfaces both
# numbers so users never have to guess which one their validator cares
# about.
SPEC_VERSION = "0.4.0"
SCHEMA_VERSION_MAX = "2.0"

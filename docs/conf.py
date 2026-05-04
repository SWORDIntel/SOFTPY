"""Sphinx configuration for crypto_standalone API docs."""

project = "crypto-standalone"
copyright = "2024, Crypto Standalone Contributors"
author = "Crypto Standalone Contributors"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
]

templates_path = ["_templates"]
exclude_patterns = ["_build"]

html_theme = "alabaster"
html_static_path = ["_static"]

autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
}

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

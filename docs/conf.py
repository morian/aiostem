# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
from __future__ import annotations

import os
import sys

# -- Path setup --------------------------------------------------------------

# This seems somehow necessary to have linkcode work properly on ReadTheDocs.
# See https://github.com/readthedocs/readthedocs.org/issues/2139#issuecomment-352188629
sys.path.insert(0, os.path.abspath('..'))


# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration
author = 'Romain Bezut'
project = 'aiostem'
copyright = f'2024, {author}'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.intersphinx',
    'sphinx.ext.napoleon',
    'sphinx_copybutton',
    'sphinx_inline_tabs',
    'sphinx_autodoc_typehints',
]

templates_path = ['_templates']
exclude_patterns = ['_build']


# -- Extensions configuration ------------------------------------------------
# Nitpick configuration
nitpicky = True
nitpick_ignore = [
    # Python does not provide those under asyncio.stream, unfortunately.
    ('py:class', 'asyncio.streams.StreamReader'),
    ('py:class', 'asyncio.streams.StreamWriter'),
]

# Napoleon settings
napoleon_use_admonition_for_notes = True

# Autodoc
autodoc_default_options = {
    'show-inheritance': True,
    'member-order': 'bysource',
    'exclude-members': '__new__,__init__',
}
autodoc_class_signature = 'separated'
autoclass_content = 'class'

# Sphinx autodoc typehints
always_use_bars_union = True
typehints_defaults = 'comma'
typehints_use_signature = True
typehints_use_signature_return = True
typehints_use_rtype = False

# InterSphinx
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
}


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'furo'

html_theme_options = {
    'source_directory': 'docs/',
    'light_css_variables': {
        'color-brand-primary': '#306998',  # blue from logo
        'color-brand-content': '#0b487a',  # blue more saturated and less dark
    },
    'dark_css_variables': {
        'color-brand-primary': '#ffd43bcc',  # yellow from logo, more muted than content
        'color-brand-content': '#ffd43bd9',  # yellow from logo, transparent like text
    },
    'sidebar_hide_name': False,
    'top_of_page_buttons': ['view'],
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']
html_css_files = ['css/custom.css']
html_copy_source = False
html_show_sourcelink = True
html_show_sphinx = False
html_title = "AIOSTEM"

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
from __future__ import annotations

import os
import sys
from docutils import nodes
from typing import TYPE_CHECKING, Any

from sphinx.ext.intersphinx import missing_reference
from sphinx.util.inspect import TypeAliasForwardRef

if TYPE_CHECKING:
    from docutils.nodes import TextElement
    from sphinx.addnodes import pending_xref
    from sphinx.application import Sphinx
    from sphinx.config import Config
    from sphinx.environment import BuildEnvironment

# -- Path setup --------------------------------------------------------------

# This seems somehow necessary to have linkcode work properly on ReadTheDocs.
# See https://github.com/readthedocs/readthedocs.org/issues/2139#issuecomment-352188629
sys.path.insert(0, os.path.abspath('..'))


# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration
author = 'Romain Bezut'
project = 'aiostem'
copyright = f'2021-2024, {author}'

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

# Autodoc
autodoc_default_options = {
    'show-inheritance': True,
    'member-order': 'bysource',
    'exclude-members': '__new__,__init__',
}
autodoc_class_signature = 'separated'
autodoc_preserve_defaults = False
autodoc_type_aliases = {
    'EventCallbackType':  '~aiostem.controller.EventCallbackType',
}
autodoc_typehints = 'signature'
autoclass_content = 'class'


# Sphinx autodoc typehints
always_use_bars_union = True
typehints_defaults = 'comma'
typehints_fully_qualified = False
typehints_use_signature = True
typehints_use_signature_return = True
typehints_use_rtype = False

# Napoleon settings
napoleon_use_admonition_for_notes = True
napoleon_preprocess_types = True


# InterSphinx
intersphinx_mapping = {
    'pydantic': ('https://docs.pydantic.dev/2.9', None),
    'python': ('https://docs.python.org/3', None),
}
# Map of references known to be broken by default.
# We register a custom mapper linked to intersphinx.
_reftarget_fixmap = {
    'asyncio.locks.Condition': 'asyncio.Condition',
    'asyncio.streams.StreamReader': 'asyncio.StreamReader',
    'asyncio.streams.StreamWriter': 'asyncio.StreamWriter',
}
# Map of known types that get badly requested to be a class.
_reftype_fixmap = {
    'aiostem.controller.EventCallbackType': 'data',
    # Sometimes it is looked up as a class.
    'typing.Self': 'obj',
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
html_title = 'AIOSTEM'

# See https://github.com/sphinx-doc/sphinx/issues/12300
suppress_warnings = ['config.cache']


def typehints_formatter(annotation: Any, config: Config | None = None) -> str | None:
    """Custom formatter for type hints."""
    if isinstance(annotation, TypeAliasForwardRef):
        return f':py:data:`{annotation.name}`'

    # Fall-back to the default behavior.
    return None


def custom_missing_reference(
    app: Sphinx,
    env: BuildEnvironment,
    node: pending_xref,
    contnode: TextElement,
) -> nodes.reference | None:
    """Fix references that are known not to exist."""
    reftarget = node['reftarget']

    newtarget = _reftarget_fixmap.get(reftarget)
    if newtarget is not None:
        node['reftarget'] = reftarget = newtarget

    newtype = _reftype_fixmap.get(reftarget)
    if newtype is not None:
        node['reftype'] = newtype

    if isinstance(reftarget, str) and reftarget.startswith(f'{project}.'):
        domain = env.domains[node['refdomain']]
        refdoc = node.setdefault('refdoc', env.docname)
        result = domain.resolve_xref(
            env,
            refdoc,
            app.builder,
            node['reftype'],
            reftarget,
            node,
            contnode,
        )
    else:
        result = missing_reference(app, env, node, contnode)

    # Look for an external reference now that we fixed the target or target type.
    return result


def setup(app: Sphinx) -> None:
    app.connect('missing-reference', custom_missing_reference)

# noqa: INP001
# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
from __future__ import annotations

import importlib
import inspect
import os
import sys
from typing import TYPE_CHECKING, Any

from sphinx.ext.intersphinx import missing_reference
from sphinx.util import typing as sphinx_typing
from sphinx.util.inspect import TypeAliasForwardRef

if TYPE_CHECKING:
    from docutils import nodes
    from docutils.nodes import TextElement
    from sphinx.addnodes import pending_xref
    from sphinx.application import Sphinx
    from sphinx.config import Config
    from sphinx.environment import BuildEnvironment

# -- Path setup --------------------------------------------------------------

# This seems somehow necessary to have linkcode work properly on ReadTheDocs.
# See https://github.com/readthedocs/readthedocs.org/issues/2139#issuecomment-352188629
sys.path.insert(0, os.path.abspath('..'))

# Keep a reference on the original stringify for annotations.
original_stringify_annotation = sphinx_typing.stringify_annotation


# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration
author = 'Romain Bezut'
project = 'aiostem'
copyright = f'2021-2025, {author}'  # noqa: A001

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.intersphinx',
    'sphinx.ext.linkcode',
    'sphinx.ext.napoleon',
    'sphinx_copybutton',
    'sphinx_inline_tabs',
    'sphinx_autodoc_typehints',
    'sphinx_toolbox.more_autodoc.genericalias',
    'sphinx_toolbox.more_autodoc.typevars',
    'sphinxext.opengraph',
]

templates_path = ['_templates']
exclude_patterns = ['_build']


# -- Extensions configuration ------------------------------------------------
# Nitpick configuration
nitpicky = True
nitpick_ignore = {
    ('py:class', 'pydantic_core.core_schema.ValidatorFunctionWrapHandler'),
}
nitpick_ignore_regex = {
    ('py:class', r'pydantic_core[.]core_schema[.][^.]*Schema'),
}

# Autodoc
autodoc_default_options = {
    'show-inheritance': True,
    'member-order': 'bysource',
    'exclude-members': '__new__,__init__',
}
autodoc_class_signature = 'separated'
autodoc_preserve_defaults = False
autodoc_type_aliases = {
    'EventCallbackType': '~aiostem.controller.EventCallbackType',
    'AnyHost': '~aiostem.types.AnyHost',
    'Argument': '~aiostem.utils.argument.Argument',
    'KeyTypes': '~aiostem.utils.argument.KeyTypes',
    'ValueTypes': '~aiostem.utils.argument.ValueTypes',
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
napoleon_preprocess_types = True
napoleon_use_admonition_for_notes = True

# Pygment color scheme.
pygments_style = 'github-dark'


# InterSphinx
intersphinx_mapping = {
    'cryptography': ('https://cryptography.io/en/stable', None),
    'pydantic': ('https://docs.pydantic.dev/2.12', None),
    'python': ('https://docs.python.org/3', None),
}
# Map of references known to be broken by default.
# We register a custom mapper linked to intersphinx.
_reftarget_fixmap = {
    'cryptography.hazmat.primitives._serialization.PublicFormat': (
        'cryptography.hazmat.primitives.serialization.PublicFormat'
    ),
    'PydanticCustomError': 'pydantic_core.PydanticCustomError',
    'asyncio.locks.Condition': 'asyncio.Condition',
    'asyncio.streams.StreamReader': 'asyncio.StreamReader',
    'asyncio.streams.StreamWriter': 'asyncio.StreamWriter',
    # Fixes for aiostem.structures.
    'OnionClientAuthKey': 'aiostem.structures.OnionClientAuthKey',
    # Fixes for aiostem.utils.argument.
    'KeyTypes': 'aiostem.utils.argument.KeyTypes',
    'ValueTypes': 'aiostem.utils.argument.ValueTypes',
}
# Map of known types that get badly requested to be a class.
_reftype_fixmap = {
    'aiostem.controller.EventCallbackType': 'data',
    'aiostem.reply._ReplyMapDefault': 'data',
    'aiostem.types.AnyHost': 'data',
    'aiostem.types.AnyPort': 'data',
    'aiostem.types.HiddenServiceAddress': 'data',
    'aiostem.utils.argument.Argument': 'data',
    'aiostem.utils.argument.KeyTypes': 'data',
    'aiostem.utils.argument.ValueTypes': 'data',
    'aiostem.utils.encoding.T': 'data',
    'aiostem.structures.OnionClientAuthKey': 'data',
    # Sometimes these are looked up as classes.
    'typing.Annotated': 'obj',
    'typing.Final': 'obj',
    'typing.Self': 'obj',
    'typing.Union': 'obj',
}

# OpenGraph URL and image.
ogp_image = '_static/aiostem.png'
ogp_site_url = os.environ.get(
    'READTHEDOCS_CANONICAL_URL',
    'https://aiostem.readthedocs.io/en/latest/',
)

# Tell Jinja2 templates the build is running on Read the Docs
if os.environ.get('READTHEDOCS') == 'True':
    if 'html_context' not in globals():
        html_context = {}

    # This is required by furo to display a link to the github repository.
    # When furo will be updated everything should come to order.
    html_context.update(
        {
            'github_user': 'morian',
            'github_repo': project,
            'display_github': True,
            'slug': project,
            'READTHEDOCS': True,
        }
    )


def get_current_commit() -> str:
    """Try to find out which commit we're building for."""
    # READTHEDOCS_GIT_IDENTIFIER does not seem to contain the tag name.
    ver_type = os.environ.get('READTHEDOCS_VERSION_TYPE', '')
    ver_name = os.environ.get('READTHEDOCS_VERSION_NAME', '')
    if ver_type == 'tag' and ver_name.startswith('v'):
        commit = ver_name
    else:
        commit = os.environ.get('READTHEDOCS_GIT_COMMIT_HASH', 'master')

    return commit


commit = get_current_commit()
repo_url = f'https://github.com/morian/{project}/'


def linkcode_resolve(domain, info):
    """Create a link to the mentioned source code."""
    if domain != 'py':
        return None

    mod = importlib.import_module(info['module'])
    if '.' in info['fullname']:
        objname, attrname = info['fullname'].split('.')
        obj = getattr(mod, objname)
        try:
            # object is a method of a class
            obj = getattr(obj, attrname)
        except AttributeError:
            # object is an attribute of a class
            return None
    else:
        obj = getattr(mod, info['fullname'])

    try:
        file = inspect.getsourcefile(obj)
        lines = inspect.getsourcelines(obj)
    except TypeError:
        # e.g. object is a typing.Union
        return None

    file = os.path.relpath(file, os.path.abspath('..'))
    if not file.startswith(project):
        # e.g. object is a typing.NewType
        return None

    start, end = lines[1], lines[1] + len(lines[0]) - 1
    return f'{repo_url}/blob/{commit}/{file}#L{start}-L{end}'


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'furo'
html_theme_options = {
    'source_branch': commit,
    'source_directory': 'docs/',
    'source_repository': repo_url,
    'light_css_variables': {
        'color-brand-primary': '#306998',  # blue from logo
        'color-brand-content': '#0b487a',  # blue more saturated and less dark
    },
    'dark_css_variables': {
        'color-brand-primary': '#ffd43bcc',  # yellow from logo, more muted than content
        'color-brand-content': '#ffd43bd9',  # yellow from logo, transparent like text
    },
    'sidebar_hide_name': True,
    'top_of_page_buttons': ['view'],
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']
html_css_files = ['css/custom.css']
html_copy_source = False
html_favicon = '_static/favicon.png'
html_logo = '_static/aiostem.png'
html_show_sourcelink = True
html_show_sphinx = False
html_title = 'AioStem'

# Define the canonical URL if you are using a custom domain on ReadTheDocs.
html_baseurl = os.environ.get('READTHEDOCS_CANONICAL_URL', '')

# See https://github.com/sphinx-doc/sphinx/issues/12300
suppress_warnings = ['config.cache']

def stringify_annotation(
    annotation: Any,
    /,
    mode: str = 'fully-qualified-except-typing',
    *,
    short_literals: bool = False,
) -> str:
    """Format the annotation properly when it is an alias forward reference."""
    if isinstance(annotation, TypeAliasForwardRef):
        return annotation.name
    return original_stringify_annotation(annotation, mode=mode, short_literals=short_literals)

def typehints_formatter(annotation: Any, config: Config | None = None) -> str | None:
    """Format type hints with some custom additions."""
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
    """Add a custom method for missing references."""
    app.connect('missing-reference', custom_missing_reference)
    sphinx_typing.stringify_annotation = stringify_annotation

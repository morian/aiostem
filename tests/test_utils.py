from __future__ import annotations

import pytest

from aiostem import utils


class TestUtils:
    @pytest.mark.parametrize(
        ('address', 'success'),
        [
            ('facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid', False),
            ('facebookcorewww1', False),
            ('facebookcore', False),
            ('facebookcorewwwi', True),
        ],
    )
    def test_onion_v2(self, address, success):
        assert utils.is_valid_hs_v2_address(address) == success, address

    @pytest.mark.parametrize(
        ('address', 'success'),
        [
            ('facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid', True),
            ('facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwib', False),
            ('facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixsad', False),
            ('facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixw1d', False),
            ('facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqol', False),
        ],
    )
    def test_onion_v3(self, address, success):
        assert utils.is_valid_hs_v3_address(address) == success, address

    @pytest.mark.parametrize(
        ('address', 'result'),
        [
            ('facebookcorewwwi.onion', 'facebookcorewwwi'),
            ('facebookcorewwwi', 'facebookcorewwwi'),
            (
                'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid.onion',
                'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid',
            ),
            (
                'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid',
                'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid',
            ),
        ],
    )
    def test_onion_strip_tld(self, address, result):
        assert utils.hs_address_strip_tld(address) == result

    @pytest.mark.parametrize(
        ('address', 'version'),
        [
            ('facebookcorewwwi.onion', 2),
            ('facebookcorewwwi', 2),
            ('facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid.onion', 3),
            ('facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixwid', 3),
        ],
    )
    def test_onion_good_version(self, address, version):
        has_tld = address.endswith('.onion')
        assert utils.hs_address_version(address, allow_suffix=has_tld) == version

    @pytest.mark.parametrize(
        'address',
        [
            'facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixw1d',
            'facebookcorewwwi.onion',
            'facebookcorewww1',
        ],
    )
    def test_onion_bad_version(self, address):
        with pytest.raises(ValueError, match='Invalid hidden service address'):
            utils.hs_address_version(address)

    @pytest.mark.parametrize(
        ('address', 'result'),
        [
            ('facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolvojixw1d', False),
            ('facebookcorewwwi.onion', True),
            ('facebookcorewww1', False),
        ],
    )
    def test_is_valid_onion_address(self, address, result):
        has_tld = address.endswith('.onion')
        assert utils.is_valid_hs_address(address, allow_suffix=has_tld) == result

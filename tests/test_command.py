import pytest

from aiostem.command import Command


def test_complex_command():
    cmd = Command('TEST')
    cmd.add_data('First line!')
    cmd.add_data('.Dot line.')
    cmd.add_arg('myarg')
    cmd.add_kwarg('key', 'value')

    assert cmd.name == 'TEST'
    assert cmd.data == 'First line!\n.Dot line.'
    assert len(cmd.arguments) == 2
    assert str(cmd) == (
        '+TEST myarg key=value\r\n'
        'First line!\r\n'
        '..Dot line.\r\n'
        '.\r\n'
    )

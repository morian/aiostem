from __future__ import annotations

from aiostem.protocol import CommandGetConf, CommandSetConf


class TestCommands:
    """Test all commands."""

    def test_getconf(self):
        cmd = CommandGetConf(keywords=['ControlPort', 'PIDFile'])
        text = cmd.serialize()
        assert text == 'GETCONF ControlPort PIDFile\r\n'

    def test_setconf_with_value(self):
        cmd = CommandSetConf(values={'ControlPort': '9872'})
        text = cmd.serialize()
        assert text == 'SETCONF ControlPort=9872\r\n'

    def test_setconf_with_null(self):
        cmd = CommandSetConf(values={'ControlPort': None})
        text = cmd.serialize()
        assert text == 'SETCONF ControlPort\r\n'

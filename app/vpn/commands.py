"""Command templates and builders for VPN management."""

from typing import List, Optional, Dict
from dataclasses import dataclass
from pathlib import Path


class CommandError(Exception):
    """Base exception for command-related errors."""
    pass


class ValidationError(CommandError):
    """Raised when command validation fails."""
    pass


@dataclass
class Command:
    """Command builder with validation."""
    base_cmd: List[str]
    use_sudo: bool = False
    _valid_options: Optional[Dict[str, type]] = None

    def _validate_option(self, opt: str, value: Optional[str]) -> None:
        """Validate option and its value if validation rules exist."""
        if self._valid_options is not None:
            # Remove leading dashes for validation
            opt_name = opt.lstrip('-').replace('-', '_')

            if opt_name not in self._valid_options:
                valid_opts = ", ".join(f"--{opt.replace('_', '-')}"
                                       for opt in self._valid_options.keys())
                raise ValidationError(
                    f"Invalid option '{opt}' for command {self.base_cmd[0]}. "
                    f"Valid options are: {valid_opts}"
                )

            if value is not None:
                expected_type = self._valid_options[opt_name]
                try:
                    if expected_type == Path:
                        Path(value)
                    else:
                        expected_type(value)
                except ValueError:
                    raise ValidationError(
                        f"Invalid value '{value}' for option '{opt}'. Expected {expected_type.__name__}"
                    )

    def _validate_executable(self) -> None:
        """Validate that base command exists."""
        if not self.base_cmd:
            raise ValidationError("Command cannot be empty")

        # Could add more validation like checking if command exists in PATH
        # import shutil
        # if not shutil.which(self.base_cmd[0]):
        #     raise ValidationError(f"Command '{self.base_cmd[0]}' not found")

    @classmethod
    def from_str(cls, cmd: str, use_sudo: bool = False, valid_options: Optional[Dict[str, type]] = None) -> 'Command':
        """Create command from string with optional validation rules."""
        command = cls(cmd.split(), use_sudo, valid_options)
        command._validate_executable()
        return command

    def with_arg(self, arg: str) -> 'Command':
        """Add single argument."""
        return Command(self.base_cmd + [arg], self.use_sudo, self._valid_options)

    def with_args(self, *args: str) -> 'Command':
        """Add multiple arguments."""
        return Command(self.base_cmd + list(args), self.use_sudo, self._valid_options)

    def with_option(self, opt: str, value: Optional[str] = None) -> 'Command':
        """Add option with validation."""
        opt_clean = opt.lstrip('-')
        self._validate_option(opt_clean, value)
        cmd = self.base_cmd.copy()
        cmd.append(f"--{opt_clean}")
        if value is not None:
            cmd.append(str(value))
        return Command(cmd, self.use_sudo, self._valid_options)

    def with_options(self, **kwargs: str) -> 'Command':
        """Add multiple options with validation."""
        cmd = self.base_cmd.copy()
        for opt, value in kwargs.items():
            print(f"Processing option: {opt} with value: {value}")
            opt_str = "--" + opt.replace("_", "-")
            print(f"Option string after conversion: {opt_str}")
            self._validate_option(opt, str(value) if value is not None else None)
            # cmd.append(f"--{opt.replace('_', '-')}")
            cmd.append(opt_str)
            if value is not None:
                cmd.append(str(value))
        return Command(cmd, self.use_sudo, self._valid_options)

    def as_sudo(self) -> 'Command':
        """Mark command to be executed with sudo."""
        return Command(self.base_cmd, True, self._valid_options)

    def build(self) -> List[str]:
        """Get final command list."""
        self._validate_executable()
        return ["sudo"] + self.base_cmd if self.use_sudo else self.base_cmd


CURL_OPTIONS = {
    'interface': str,
    'silent': type(None),
    'max_time': int,
}

IP_OPTIONS = {
    'link': type(None),
    'addr': type(None),
    'route': type(None),
    'rule': type(None),
    'table': str,
}

OPENVPN_OPTIONS = {
    'config': Path,
    'auth_user_pass': Path,
    'daemon': type(None),
    'verb': int,
    'log': Path,
    'persist_tun': type(None),
    # 'persist_key': type(None),
    # 'script_security': int,
    # 'user': str,
    # 'group': str,
    'dev': str,
}

SHELL_OPTIONS = {
    'c': str,
}


BASH = Command.from_str("bash", valid_options=SHELL_OPTIONS)

CAT = Command.from_str("cat")

IP = Command.from_str("ip", valid_options=IP_OPTIONS)
IP_LINK = IP.with_arg("link")
IP_ADDR = IP.with_arg("addr")
IP_ROUTE = IP.with_arg("route")
IP_RULE = IP.with_arg("rule")

IP_RULE_DEL = IP_RULE.with_arg("del")
IP_RULE_FLUSH = IP_RULE.with_arg("flush")

CHECK_IP = (
    Command.from_str("curl", valid_options=CURL_OPTIONS)
    .with_options(
        silent=None,
        max_time="10",
    )
    .with_arg("ifconfig.me")
)

KILLALL = Command.from_str("killall")

OPENVPN = Command.from_str("openvpn", valid_options=OPENVPN_OPTIONS)
OPENVPN_START = (
    OPENVPN
    .with_options(
        daemon=None,
        verb="4",
        persist_tun=None,
        # persist_key=None,
        # script_security="2",
        # user="root",
        # group="root"
    )
)

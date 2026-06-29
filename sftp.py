import contextlib
import functools
import pathlib
from collections.abc import AsyncGenerator
from typing import Any

import asyncssh
import rich


class SSHServer(asyncssh.SSHServer):
    active_connections: set[asyncssh.SSHServerConnection] = set()

    def __init__(
        self,
        *args: Any,
        allowed_username: str | None = None,
        allowed_password: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.conn: asyncssh.SSHServerConnection | None = None
        self.allowed_username = allowed_username
        self.allowed_password = allowed_password

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        ip, port = "", ""
        is_ok = False
        if self.conn:
            ip, port = self.conn.get_extra_info("peername")
            self.conn.set_extra_info(username=username, ip=ip, port=port)
        if self.allowed_username and self.allowed_password:
            is_ok = username == self.allowed_username and password == self.allowed_password
        rich.print(f"Login: username={username}, IP={ip}, port={port}, success={is_ok}")
        return is_ok

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        self.__class__.active_connections.add(conn)
        super().connection_made(conn)

    def connection_lost(self, exc: Exception | None) -> None:
        if self.conn in self.__class__.active_connections:
            username = self.conn.get_extra_info("username")
            ip = self.conn.get_extra_info("ip")
            port = self.conn.get_extra_info("port")
            rich.print(f"Disconnect: username={username}, IP={ip}, port={port}")
            self.__class__.active_connections.remove(self.conn)
        super().connection_lost(exc)

    @classmethod
    async def close_all_connections(cls) -> None:
        for conn in list(cls.active_connections):
            conn.close()
            await conn.wait_closed()


class SFTPServer(asyncssh.SFTPServer):
    def __init__(self, chan: asyncssh.SSHServerChannel, root_dir: bytes) -> None:
        super().__init__(chan, root_dir)

    def open(self, path: bytes, pflags: int, attrs: asyncssh.SFTPAttrs) -> object:
        username = self.connection.get_extra_info("username")
        ip = self.connection.get_extra_info("ip")
        port = self.connection.get_extra_info("port")
        rich.print(f"Open: path={path.decode()}, username={username}, IP={ip}, port={port}")
        return super().open(path, pflags, attrs)

    def remove(self, path: bytes) -> None:
        raise asyncssh.SFTPError(asyncssh.constants.FX_PERMISSION_DENIED, "Deletion is not allowed")

    def rmdir(self, path: bytes) -> None:
        raise asyncssh.SFTPError(asyncssh.constants.FX_PERMISSION_DENIED, "Deletion is not allowed")


@contextlib.asynccontextmanager
async def start_sftp_server(
    port: int, allowed_username: str, allowed_password: str, root_dir: str
) -> AsyncGenerator[None, None]:
    """
    Start a simple SSH server that only allows SFTP connections, restricted to root_dir.

    Args:
        port: The port to listen on.
        allowed_username: The username required.
        allowed_password: The password required.
        root_dir: The directory to serve.
    """

    private_key_file, public_key_file = ensure_ssh_keys()

    listener = await asyncssh.listen(
        "",  # Listen on all interfaces
        port=port,
        server_host_keys=[private_key_file],
        server_factory=functools.partial(
            SSHServer, allowed_username=allowed_username, allowed_password=allowed_password
        ),
        sftp_factory=functools.partial(SFTPServer, root_dir=root_dir.encode()),
        password_auth=True,
        public_key_auth=False,
    )

    try:
        yield
    finally:
        listener.close()
        await SSHServer.close_all_connections()


def ensure_ssh_keys() -> tuple[str, str]:
    """
    Ensures SSH key pair exists in the default user directory, generating new keys if missing.

    Returns:
        tuple[str, str]: Paths to the private key file and public key file, in that order.
    """
    home_dir = pathlib.Path.home()
    ssh_dir = home_dir / ".ssh"
    private_key_file = ssh_dir / "id_rsa"
    public_key_file = ssh_dir / "id_rsa.pub"

    ssh_dir.mkdir(exist_ok=True)

    if not private_key_file.exists() or not public_key_file.exists():
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(str(private_key_file))
        key.write_public_key(str(public_key_file))

    return str(private_key_file), str(public_key_file)

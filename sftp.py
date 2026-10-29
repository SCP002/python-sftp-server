import asyncio
import contextlib
import functools
import pathlib
import secrets
from collections.abc import AsyncGenerator

import asyncssh
import rich


class SSHServer(asyncssh.SSHServer):
    def __init__(
        self,
        *,
        connections: set[asyncssh.SSHServerConnection],
        allowed_username: str,
        allowed_password: str,
    ) -> None:
        super().__init__()
        self.conn: asyncssh.SSHServerConnection | None = None
        self.connections = connections
        self.allowed_username = allowed_username
        self.allowed_password = allowed_password

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        is_ok = False
        if self.allowed_username and self.allowed_password:
            # Non-short-circuit "&" and constant-time comparison to avoid leaking timing info
            is_ok = secrets.compare_digest(username.encode(), self.allowed_username.encode()) & secrets.compare_digest(
                password.encode(), self.allowed_password.encode()
            )
        if self.conn:
            self.conn.set_extra_info(username=username)
        rich.print(f"Login: {_describe_client(self.conn)}, success={is_ok}")
        return is_ok

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        # IPv6 peername is a 4-tuple, so take only the first two items
        ip, port = conn.get_extra_info("peername")[:2]
        conn.set_extra_info(ip=ip, port=port)
        self.connections.add(conn)
        super().connection_made(conn)

    def connection_lost(self, exc: Exception | None) -> None:
        if self.conn in self.connections:
            rich.print(f"Disconnect: {_describe_client(self.conn)}")
            self.connections.remove(self.conn)
        super().connection_lost(exc)


class SFTPServer(asyncssh.SFTPServer):
    """SFTP server which allows to read files and upload new ones, but forbids deleting or overwriting existing data."""

    def open(self, path: bytes, pflags: int, attrs: asyncssh.SFTPAttrs) -> object:
        rich.print(f"Open: path={path.decode(errors='replace')}, {_describe_client(self.connection)}")
        if pflags & (asyncssh.constants.FXF_WRITE | asyncssh.constants.FXF_APPEND | asyncssh.constants.FXF_TRUNC):
            self._deny_if_exists(path, "Modifying existing files is not allowed")
        return super().open(path, pflags, attrs)

    def open56(self, path: bytes, desired_access: int, flags: int, attrs: asyncssh.SFTPAttrs) -> object:
        rich.print(f"Open: path={path.decode(errors='replace')}, {_describe_client(self.connection)}")
        if desired_access & (asyncssh.constants.ACE4_WRITE_DATA | asyncssh.constants.ACE4_APPEND_DATA):
            self._deny_if_exists(path, "Modifying existing files is not allowed")
        return super().open56(path, desired_access, flags, attrs)

    def remove(self, path: bytes) -> None:
        raise asyncssh.SFTPPermissionDenied("Deletion is not allowed")

    def rmdir(self, path: bytes) -> None:
        raise asyncssh.SFTPPermissionDenied("Deletion is not allowed")

    def posix_rename(self, oldpath: bytes, newpath: bytes) -> None:
        # Unlike rename(), posix_rename() replaces the existing target
        self._deny_if_exists(newpath, "Overwriting is not allowed")
        super().posix_rename(oldpath, newpath)

    def setstat(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        self._deny_truncate(attrs)
        super().setstat(path, attrs)

    def lsetstat(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        self._deny_truncate(attrs)
        super().lsetstat(path, attrs)

    def fsetstat(self, file_obj: object, attrs: asyncssh.SFTPAttrs) -> None:
        self._deny_truncate(attrs)
        super().fsetstat(file_obj, attrs)

    def _deny_if_exists(self, path: bytes, reason: str) -> None:
        # Use lstat() rather than os.path, as it handles asyncssh's internal path format (e.g. "/C:/..." on Windows)
        try:
            self.lstat(path)
        except OSError:
            return
        raise asyncssh.SFTPPermissionDenied(reason)

    @staticmethod
    def _deny_truncate(attrs: asyncssh.SFTPAttrs) -> None:
        if attrs.size is not None:
            raise asyncssh.SFTPPermissionDenied("Changing file size is not allowed")


def _describe_client(conn: asyncssh.SSHServerConnection | None) -> str:
    if conn is None:
        return "username=None, IP=None, port=None"
    username = conn.get_extra_info("username")
    ip = conn.get_extra_info("ip")
    port = conn.get_extra_info("port")
    return f"username={username}, IP={ip}, port={port}"


@contextlib.asynccontextmanager
async def start_sftp_server(
    port: int, allowed_username: str, allowed_password: str, root_dir: str
) -> AsyncGenerator[None]:
    """
    Start a simple SSH server that only allows SFTP connections, restricted to root_dir.
    Clients can read files and upload new ones, but can't delete or overwrite existing data.

    Args:
        port: The port to listen on.
        allowed_username: The username required.
        allowed_password: The password required.
        root_dir: The directory to serve.
    """
    connections: set[asyncssh.SSHServerConnection] = set()

    listener = await asyncssh.listen(
        "",  # Listen on all interfaces
        port=port,
        server_host_keys=[ensure_host_key()],
        server_factory=functools.partial(
            SSHServer, connections=connections, allowed_username=allowed_username, allowed_password=allowed_password
        ),
        sftp_factory=functools.partial(SFTPServer, chroot=root_dir.encode()),
        password_auth=True,
        public_key_auth=False,
    )

    try:
        yield
    finally:
        listener.close()
        await listener.wait_closed()
        for conn in list(connections):
            conn.close()
        await asyncio.gather(*(conn.wait_closed() for conn in list(connections)))


def ensure_host_key() -> str:
    """
    Ensures SSH server host key exists in the default user directory, generating a new one if missing.

    Returns:
        Path to the private key file.
    """
    ssh_dir = pathlib.Path.home() / ".ssh"
    private_key_file = ssh_dir / "sftp_server_ed25519_key"

    ssh_dir.mkdir(exist_ok=True)

    if not private_key_file.exists():
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(str(private_key_file))
        key.write_public_key(str(private_key_file.with_name(private_key_file.name + ".pub")))

    return str(private_key_file)

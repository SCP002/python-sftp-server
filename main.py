#! /usr/bin/env uv run

import asyncio

import sftp


async def main() -> None:
    ssh_port = 22
    root_dir = r"C:/"
    username = "admin"
    password = "mypassword"

    print(f"Starting SFTP server at port {ssh_port}")
    async with sftp.start_sftp_server(ssh_port, username, password, root_dir):
        print("Press <Enter> to stop SFTP server and exit")
        await asyncio.to_thread(input)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(e)
        print("Press <Enter> to exit...")
        input()

import pytest

from deprisk.github_repository import (
    GitHubRepository,
    GitHubRepositoryError,
    parse_github_repository_url,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://github.com/octo-org/sample-repo",
            GitHubRepository("octo-org", "sample-repo"),
        ),
        (
            "https://github.com/octo-org/sample-repo/",
            GitHubRepository("octo-org", "sample-repo"),
        ),
        (
            "https://github.com/octo-org/sample-repo.git",
            GitHubRepository("octo-org", "sample-repo"),
        ),
        (
            "https://github.com/Owner123/Repo.Name_2",
            GitHubRepository("Owner123", "Repo.Name_2"),
        ),
    ],
)
def test_parses_supported_github_repository_urls(
    url: str,
    expected: GitHubRepository,
) -> None:
    result = parse_github_repository_url(url)

    assert result == expected
    assert result.canonical_url == (f"https://github.com/{expected.owner}/{expected.repository}")


@pytest.mark.parametrize(
    "url",
    [
        "",
        " https://github.com/octo-org/repo",
        "https://github.com.evil.example/octo-org/repo",
        "https://evil.example/github.com/octo-org/repo",
        "http://github.com/octo-org/repo",
        "https://user@github.com/octo-org/repo",
        "https://user:password@github.com/octo-org/repo",
        "https://github.com:8443/octo-org/repo",
        "https://github.com/octo-org/repo?download=1",
        "https://github.com/octo-org/repo#archive",
        "https://github.com/octo-org/repo/tree/main",
        "https://github.com/octo-org",
        "https://github.com/octo-org/repo/extra",
        "https://github.com/octo-org/%2e%2e",
        "https://github.com/-invalid/repo",
        "https://github.com/invalid-/repo",
        "https://github.com/octo-org/..",
        "https://github.com/octo-org/repo..name",
        "https://github.com/octo-org/repo.",
    ],
)
def test_rejects_unsupported_github_repository_urls(url: str) -> None:
    with pytest.raises(GitHubRepositoryError):
        parse_github_repository_url(url)


def test_rejects_non_string_input() -> None:
    with pytest.raises(GitHubRepositoryError):
        parse_github_repository_url(None)  # type: ignore[arg-type]


def test_resolves_public_github_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 443, 0, 0)),
    ]

    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)

    from deprisk.github_repository import resolve_public_github_addresses

    result = resolve_public_github_addresses("github.com")

    assert result == ("2606:4700:4700::1111", "93.184.216.34")


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.10",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "fe80::1",
    ],
)
def test_rejects_non_public_dns_addresses(
    monkeypatch: pytest.MonkeyPatch,
    address: str,
) -> None:
    import socket

    records = [
        (
            socket.AF_INET if ":" not in address else socket.AF_INET6,
            socket.SOCK_STREAM,
            6,
            "",
            (address, 443),
        )
    ]

    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)

    from deprisk.github_repository import resolve_public_github_addresses

    with pytest.raises(GitHubRepositoryError, match="non-public"):
        resolve_public_github_addresses("github.com")


def test_rejects_unapproved_dns_hostname() -> None:
    from deprisk.github_repository import resolve_public_github_addresses

    with pytest.raises(GitHubRepositoryError, match="not allowed"):
        resolve_public_github_addresses("github.com.evil.example")


def test_rejects_empty_dns_result(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])

    from deprisk.github_repository import resolve_public_github_addresses

    with pytest.raises(GitHubRepositoryError, match="no IP addresses"):
        resolve_public_github_addresses("github.com")


def test_rejects_dns_resolution_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def fail_resolution(*args, **kwargs):
        raise socket.gaierror("DNS failure")

    monkeypatch.setattr(socket, "getaddrinfo", fail_resolution)

    from deprisk.github_repository import resolve_public_github_addresses

    with pytest.raises(GitHubRepositoryError, match="could not be resolved"):
        resolve_public_github_addresses("github.com")


@pytest.mark.parametrize(
    ("hostname", "address"),
    [
        ("codeload.github.com", "93.184.216.34"),
        ("api.github.com", "2606:4700:4700::1111"),
    ],
)
def test_builds_request_pinned_to_public_ip(
    hostname: str,
    address: str,
) -> None:
    import httpx

    from deprisk.github_repository import build_pinned_github_request

    original_url = f"https://{hostname}/owner/repo/archive.tar.gz"

    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
        request = build_pinned_github_request(
            client,
            original_url,
            hostname,
            address,
        )

    assert request.url.host == address
    assert request.headers["host"] == hostname
    assert request.extensions["sni_hostname"] == hostname
    assert request.url.scheme == "https"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.10",
        "::1",
        "fe80::1",
    ],
)
def test_pinned_request_rejects_non_public_ip(address: str) -> None:
    import httpx

    from deprisk.github_repository import build_pinned_github_request

    with httpx.Client() as client, pytest.raises(GitHubRepositoryError, match="must be public"):
        build_pinned_github_request(
            client,
            "https://github.com/owner/repo",
            "github.com",
            address,
        )


def test_pinned_request_rejects_unapproved_hostname() -> None:
    import httpx

    from deprisk.github_repository import build_pinned_github_request

    with httpx.Client() as client, pytest.raises(GitHubRepositoryError, match="not allowed"):
        build_pinned_github_request(
            client,
            "https://github.com.evil.example/owner/repo",
            "github.com.evil.example",
            "93.184.216.34",
        )


def test_pinned_request_rejects_hostname_mismatch() -> None:
    import httpx

    from deprisk.github_repository import build_pinned_github_request

    with httpx.Client() as client, pytest.raises(GitHubRepositoryError, match="does not match"):
        build_pinned_github_request(
            client,
            "https://evil.example/owner/repo",
            "github.com",
            "93.184.216.34",
        )


def test_downloads_tarball_after_validated_redirect() -> None:
    import asyncio

    import httpx

    from deprisk.github_repository import download_github_repository_tarball

    requests = []
    resolved_hosts = []

    class TarballStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"fake-tarball"

        async def aclose(self) -> None:
            pass

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)

        if request.headers["host"] == "api.github.com":
            return httpx.Response(
                302,
                headers={"location": "https://codeload.github.com/owner/repo/archive.tar.gz"},
            )

        return httpx.Response(200, stream=TarballStream())

    def resolver(hostname: str) -> tuple[str, ...]:
        resolved_hosts.append(hostname)
        return ("93.184.216.34",)

    result = asyncio.run(
        download_github_repository_tarball(
            "https://github.com/owner/repo",
            resolver=resolver,
            transport=httpx.MockTransport(handler),
        )
    )

    assert result == b"fake-tarball"
    assert len(requests) == 2
    assert requests[0].headers["host"] == "api.github.com"
    assert requests[1].headers["host"] == "codeload.github.com"
    assert all(request.url.host == "93.184.216.34" for request in requests)
    assert resolved_hosts == ["api.github.com", "codeload.github.com"]


def test_download_rejects_redirect_to_unapproved_host() -> None:
    import asyncio

    import httpx

    from deprisk.github_repository import download_github_repository_tarball

    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={"location": "https://evil.example/archive.tar.gz"},
        )

    with pytest.raises(GitHubRepositoryError, match="redirect destination"):
        asyncio.run(
            download_github_repository_tarball(
                "https://github.com/owner/repo",
                resolver=lambda hostname: ("93.184.216.34",),
                transport=httpx.MockTransport(handler),
            )
        )

    assert len(requests) == 1


def test_download_rejects_too_many_redirects() -> None:
    import asyncio

    import httpx

    from deprisk.github_repository import download_github_repository_tarball

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": (f"https://{request.headers['host']}/another-redirect")},
        )

    with pytest.raises(GitHubRepositoryError, match="redirect limit"):
        asyncio.run(
            download_github_repository_tarball(
                "https://github.com/owner/repo",
                resolver=lambda hostname: ("93.184.216.34",),
                transport=httpx.MockTransport(handler),
            )
        )


def test_download_rejects_oversized_content_length() -> None:
    import asyncio

    import httpx

    from deprisk.github_repository import download_github_repository_tarball

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": "6"},
            content=b"123456",
        )

    with pytest.raises(GitHubRepositoryError, match="size limit"):
        asyncio.run(
            download_github_repository_tarball(
                "https://github.com/owner/repo",
                max_bytes=5,
                resolver=lambda hostname: ("93.184.216.34",),
                transport=httpx.MockTransport(handler),
            )
        )


def test_download_rejects_oversized_stream_without_content_length() -> None:
    import asyncio

    import httpx

    from deprisk.github_repository import download_github_repository_tarball

    class OversizedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"123"
            yield b"456"

        async def aclose(self) -> None:
            pass

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=OversizedStream())

    with pytest.raises(GitHubRepositoryError, match="size limit"):
        asyncio.run(
            download_github_repository_tarball(
                "https://github.com/owner/repo",
                max_bytes=5,
                resolver=lambda hostname: ("93.184.216.34",),
                transport=httpx.MockTransport(handler),
            )
        )


def test_download_rejects_unexpected_http_status() -> None:
    import asyncio

    import httpx

    from deprisk.github_repository import download_github_repository_tarball

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    with pytest.raises(GitHubRepositoryError, match="HTTP 404"):
        asyncio.run(
            download_github_repository_tarball(
                "https://github.com/owner/repo",
                resolver=lambda hostname: ("93.184.216.34",),
                transport=httpx.MockTransport(handler),
            )
        )


def test_download_rejects_dns_failure() -> None:
    import asyncio

    import httpx

    from deprisk.github_repository import download_github_repository_tarball

    def resolver(hostname: str) -> tuple[str, ...]:
        raise OSError("DNS unavailable")

    with pytest.raises(GitHubRepositoryError, match="resolution failed"):
        asyncio.run(
            download_github_repository_tarball(
                "https://github.com/owner/repo",
                resolver=resolver,
                transport=httpx.MockTransport(lambda request: httpx.Response(200)),
            )
        )


def test_download_enforces_overall_timeout_during_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    import httpx

    from deprisk.github_repository import download_github_repository_tarball

    async def immediate_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", immediate_to_thread)

    class SlowStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.sleep(0.1)
            yield b"slow-data"

        async def aclose(self) -> None:
            pass

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=SlowStream())

    with pytest.raises(
        GitHubRepositoryError,
        match="interrupted or timed out",
    ):
        asyncio.run(
            download_github_repository_tarball(
                "https://github.com/owner/repo",
                timeout_seconds=0.02,
                resolver=lambda hostname: ("93.184.216.34",),
                transport=httpx.MockTransport(handler),
            )
        )


def test_download_rejects_insecure_redirect_and_closes_response() -> None:
    import asyncio

    import httpx

    from deprisk.github_repository import download_github_repository_tarball

    stream_closed = []

    class RedirectStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b""

        async def aclose(self) -> None:
            stream_closed.append(True)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "http://github.com.evil.example/archive.tar.gz"},
            stream=RedirectStream(),
        )

    with pytest.raises(
        GitHubRepositoryError,
        match="redirect destination",
    ):
        asyncio.run(
            download_github_repository_tarball(
                "https://github.com/owner/repo",
                resolver=lambda hostname: ("93.184.216.34",),
                transport=httpx.MockTransport(handler),
            )
        )

    assert stream_closed == [True]


def _build_test_github_tarball(
    members: list[tuple[str, bytes, str]],
) -> bytes:
    import io
    import tarfile

    buffer = io.BytesIO()

    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, member_type in members:
            info = tarfile.TarInfo(name)

            if member_type == "directory":
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            elif member_type == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = data.decode("utf-8")
                info.size = 0
                archive.addfile(info)
            elif member_type == "file":
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                raise ValueError(f"Unsupported test member type: {member_type}")

    return buffer.getvalue()


def _valid_github_tarball() -> bytes:
    return _build_test_github_tarball(
        [
            ("sample-repo/", b"", "directory"),
            ("sample-repo/package-lock.json", b'{"lockfileVersion": 3}', "file"),
            ("sample-repo/src/index.js", b"console.log('safe');", "file"),
        ]
    )


def test_extracts_valid_github_repository_tarball() -> None:
    from deprisk.github_repository import extract_github_repository_tarball

    archive = _valid_github_tarball()

    with extract_github_repository_tarball(archive) as repository_path:
        lockfile = repository_path / "package-lock.json"
        source_file = repository_path / "src" / "index.js"

        assert lockfile.is_file()
        assert lockfile.read_text(encoding="utf-8") == '{"lockfileVersion": 3}'
        assert source_file.read_text(encoding="utf-8") == "console.log('safe');"


def test_extraction_directory_is_removed_after_context() -> None:
    from deprisk.github_repository import extract_github_repository_tarball

    with extract_github_repository_tarball(_valid_github_tarball()) as path:
        extraction_path = path
        assert extraction_path.exists()

    assert not extraction_path.exists()


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../escape.txt",
        "sample-repo/../escape.txt",
        "/absolute.txt",
        "sample-repo/CON",
        "sample-repo/NUL.txt",
        "sample-repo/COM1.log",
        "sample-repo/LPT9.txt",
        "sample-repo/file:stream",
        "sample-repo/trailing.",
        "sample-repo/trailing ",
        "sample-repo/bad?.txt",
        "sample-repo/back\\slash.txt",
    ],
)
def test_rejects_unsafe_or_nonportable_archive_paths(unsafe_path: str) -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _build_test_github_tarball(
        [
            ("sample-repo/", b"", "directory"),
            ("sample-repo/package-lock.json", b"{}", "file"),
            (unsafe_path, b"unsafe", "file"),
        ]
    )

    with pytest.raises(GitHubRepositoryError), extract_github_repository_tarball(archive):
        pytest.fail("Unsafe archive should not be extracted")


def test_rejects_case_insensitive_duplicate_paths() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _build_test_github_tarball(
        [
            ("sample-repo/", b"", "directory"),
            ("sample-repo/package-lock.json", b"{}", "file"),
            ("sample-repo/README.md", b"first", "file"),
            ("sample-repo/readme.md", b"second", "file"),
        ]
    )

    with (
        pytest.raises(GitHubRepositoryError, match="duplicate paths"),
        extract_github_repository_tarball(archive),
    ):
        pytest.fail("Case-insensitive duplicate should be rejected")


def test_rejects_archive_symlinks() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _build_test_github_tarball(
        [
            ("sample-repo/", b"", "directory"),
            ("sample-repo/package-lock.json", b"{}", "file"),
            ("sample-repo/link", b"../../outside", "symlink"),
        ]
    )

    with (
        pytest.raises(GitHubRepositoryError, match="unsupported"),
        extract_github_repository_tarball(archive),
    ):
        pytest.fail("Symlink should be rejected")


def test_rejects_archive_larger_than_configured_limit() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _valid_github_tarball()

    with (
        pytest.raises(GitHubRepositoryError, match="archive size limit"),
        extract_github_repository_tarball(
            archive,
            max_archive_size=len(archive) - 1,
        ),
    ):
        pytest.fail("Oversized archive should be rejected")


def test_rejects_file_larger_than_configured_limit() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _valid_github_tarball()

    with (
        pytest.raises(GitHubRepositoryError, match="oversized file"),
        extract_github_repository_tarball(
            archive,
            max_file_size=5,
        ),
    ):
        pytest.fail("Oversized file should be rejected")


def test_rejects_total_extracted_size_over_configured_limit() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _valid_github_tarball()

    with (
        pytest.raises(GitHubRepositoryError, match="extracted size limit"),
        extract_github_repository_tarball(
            archive,
            max_total_size=5,
        ),
    ):
        pytest.fail("Excessive extracted size should be rejected")


def test_rejects_archive_with_too_many_members() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _valid_github_tarball()

    with (
        pytest.raises(GitHubRepositoryError, match="member count limit"),
        extract_github_repository_tarball(
            archive,
            max_members=2,
        ),
    ):
        pytest.fail("Archive with too many members should be rejected")


def test_rejects_archive_without_root_package_lockfile() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _build_test_github_tarball(
        [
            ("sample-repo/", b"", "directory"),
            ("sample-repo/README.md", b"documentation", "file"),
        ]
    )

    with (
        pytest.raises(GitHubRepositoryError, match="root package-lock.json"),
        extract_github_repository_tarball(archive),
    ):
        pytest.fail("Archive without root lockfile should be rejected")


def test_rejects_nested_package_lockfile() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _build_test_github_tarball(
        [
            ("sample-repo/", b"", "directory"),
            ("sample-repo/src/package-lock.json", b"{}", "file"),
        ]
    )

    with (
        pytest.raises(GitHubRepositoryError, match="root package-lock.json"),
        extract_github_repository_tarball(archive),
    ):
        pytest.fail("Nested lockfile should be rejected")


def test_rejects_invalid_archive_bytes() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    with pytest.raises(GitHubRepositoryError), extract_github_repository_tarball(b"not a tarball"):
        pytest.fail("Invalid archive should be rejected")


def test_rejects_file_colliding_with_implicit_directory_case_insensitively() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _build_test_github_tarball(
        [
            ("sample-repo/", b"", "directory"),
            ("sample-repo/package-lock.json", b"{}", "file"),
            ("sample-repo/src/index.js", b"source", "file"),
            ("sample-repo/SRC", b"collision", "file"),
        ]
    )

    with (
        pytest.raises(GitHubRepositoryError, match="conflicting paths"),
        extract_github_repository_tarball(archive),
    ):
        pytest.fail("File colliding with an implicit directory should be rejected")


def test_rejects_archive_exceeding_maximum_path_depth() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _valid_github_tarball()

    with (
        pytest.raises(GitHubRepositoryError, match="unsafe or non-portable path"),
        extract_github_repository_tarball(archive, max_depth=1),
    ):
        pytest.fail("Archive exceeding maximum path depth should be rejected")


def test_rejects_archive_exceeding_maximum_path_length() -> None:
    from deprisk.github_repository import (
        GitHubRepositoryError,
        extract_github_repository_tarball,
    )

    archive = _valid_github_tarball()

    with (
        pytest.raises(GitHubRepositoryError, match="unsafe path"),
        extract_github_repository_tarball(archive, max_path_length=20),
    ):
        pytest.fail("Archive exceeding maximum path length should be rejected")


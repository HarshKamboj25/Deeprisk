"""Validation of GitHub repository identities for safe ingestion."""

import re
import tarfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,100}\Z")


class GitHubRepositoryError(ValueError):
    """Raised when a GitHub repository URL is invalid or unsupported."""


@dataclass(frozen=True, slots=True)
class GitHubRepository:
    """Validated GitHub repository identity."""

    owner: str
    repository: str

    @property
    def canonical_url(self) -> str:
        """Return the canonical HTTPS repository URL."""
        return f"https://github.com/{self.owner}/{self.repository}"


def parse_github_repository_url(url: str) -> GitHubRepository:
    """Validate and parse a canonical GitHub repository URL.

    Only HTTPS URLs for github.com with an owner and repository path
    are accepted. Branches, archive URLs, query strings and fragments
    must not be supplied as part of the repository identity.
    """
    if not isinstance(url, str) or not url:
        raise GitHubRepositoryError("GitHub repository URL must be a non-empty string")

    if url != url.strip():
        raise GitHubRepositoryError("GitHub repository URL must not contain surrounding whitespace")

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise GitHubRepositoryError("GitHub repository URL is malformed") from exc

    if parsed.scheme.lower() != "https":
        raise GitHubRepositoryError("GitHub repository URL must use HTTPS")

    if hostname is None or hostname.lower() != "github.com":
        raise GitHubRepositoryError("Only github.com repository URLs are supported")

    if parsed.username is not None or parsed.password is not None:
        raise GitHubRepositoryError("GitHub repository URL must not contain credentials")

    if port is not None:
        raise GitHubRepositoryError("GitHub repository URL must not specify a port")

    if parsed.query or parsed.fragment:
        raise GitHubRepositoryError("GitHub repository URL must not contain a query or fragment")

    if "%" in parsed.path or "\\" in parsed.path:
        raise GitHubRepositoryError("GitHub repository path contains unsupported encoding")

    segments = parsed.path.strip("/").split("/")

    if len(segments) != 2 or not all(segments):
        raise GitHubRepositoryError("GitHub URL must identify exactly one owner and one repository")

    owner, repository = segments

    if _OWNER_PATTERN.fullmatch(owner) is None:
        raise GitHubRepositoryError("GitHub repository owner is invalid")

    if repository.endswith(".git"):
        repository = repository[:-4]

    if (
        _REPOSITORY_PATTERN.fullmatch(repository) is None
        or repository in {".", ".."}
        or repository.endswith(".")
        or ".." in repository
    ):
        raise GitHubRepositoryError("GitHub repository name is invalid")

    return GitHubRepository(owner=owner, repository=repository)


def resolve_public_github_addresses(hostname: str) -> tuple[str, ...]:
    """Resolve an approved GitHub hostname and reject non-public addresses."""
    import ipaddress
    import socket

    allowed_hosts = {
        "api.github.com",
        "github.com",
        "codeload.github.com",
    }

    if not isinstance(hostname, str) or hostname.lower() not in allowed_hosts:
        raise GitHubRepositoryError("GitHub download host is not allowed")

    try:
        records = socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise GitHubRepositoryError("GitHub hostname could not be resolved") from exc

    addresses: set[str] = set()

    for record in records:
        address = record[4][0]

        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as exc:
            raise GitHubRepositoryError("DNS returned an invalid IP address") from exc

        if not parsed_address.is_global:
            raise GitHubRepositoryError("GitHub hostname resolved to a non-public IP address")

        addresses.add(str(parsed_address))

    if not addresses:
        raise GitHubRepositoryError("GitHub hostname returned no IP addresses")

    return tuple(sorted(addresses))


def build_pinned_github_request(
    client: Any, url: str, hostname: str, address: str
) -> Any:
    """Build an HTTPS request pinned to a validated public IP address."""
    import ipaddress

    import httpx

    allowed_hosts = {
        "api.github.com",
        "github.com",
        "codeload.github.com",
    }

    if not isinstance(hostname, str) or hostname.lower() not in allowed_hosts:
        raise GitHubRepositoryError("GitHub download host is not allowed")

    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise GitHubRepositoryError("Pinned IP address is invalid") from exc

    if not parsed_address.is_global:
        raise GitHubRepositoryError("Pinned IP address must be public")

    try:
        original_url = httpx.URL(url)
    except (TypeError, ValueError) as exc:
        raise GitHubRepositoryError("GitHub download URL is invalid") from exc

    if (
        original_url.scheme != "https"
        or original_url.host.lower() != hostname.lower()
        or original_url.username
        or original_url.password
        or original_url.port not in (None, 443)
        or original_url.fragment
    ):
        raise GitHubRepositoryError("GitHub download URL does not match its approved hostname")

    pinned_url = original_url.copy_with(host=str(parsed_address))

    return client.build_request(
        "GET",
        pinned_url,
        headers={"Host": hostname},
        extensions={"sni_hostname": hostname},
    )


async def download_github_repository_tarball(
    repository_url: str,
    *,
    max_bytes: int = 100 * 1024 * 1024,
    timeout_seconds: float = 120.0,
    resolver: Any = None,
    transport: Any = None,
) -> bytes:
    """Download a GitHub repository tarball with validated, pinned connections."""
    import asyncio
    import os

    import httpx

    github_token = os.environ.get('GITHUB_TOKEN', '').strip()

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise GitHubRepositoryError("Download size limit must be a positive integer")

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        raise GitHubRepositoryError("Download timeout must be positive")

    repository = parse_github_repository_url(repository_url)
    current_url = f"https://api.github.com/repos/{repository.owner}/{repository.repository}/tarball"

    allowed_hosts = {
        "api.github.com",
        "github.com",
        "codeload.github.com",
    }
    redirect_statuses = {301, 302, 303, 307, 308}
    max_redirects = 3

    if resolver is None:
        resolver = resolve_public_github_addresses

    timeout = httpx.Timeout(
        timeout_seconds,
        connect=min(5.0, timeout_seconds),
    )

    limits = httpx.Limits(
        max_connections=1,
        max_keepalive_connections=0,
    )
    deadline = asyncio.get_running_loop().time() + timeout_seconds

    async with httpx.AsyncClient(
        verify=True,
        trust_env=False,
        follow_redirects=False,
        timeout=timeout,
        limits=limits,
        transport=transport,
    ) as client:
        redirect_count = 0

        while True:
            try:
                parsed_url = httpx.URL(current_url)
            except (TypeError, ValueError) as exc:
                raise GitHubRepositoryError("GitHub download URL is malformed") from exc

            hostname = parsed_url.host.lower()

            if (
                parsed_url.scheme != "https"
                or hostname not in allowed_hosts
                or parsed_url.username
                or parsed_url.password
                or parsed_url.port not in (None, 443)
                or parsed_url.fragment
            ):
                raise GitHubRepositoryError("GitHub redirect destination is not allowed")

            try:
                remaining = deadline - asyncio.get_running_loop().time()
                addresses = await asyncio.wait_for(
                    asyncio.to_thread(resolver, hostname),
                    timeout=max(remaining, 0.0),
                )
            except GitHubRepositoryError:
                raise
            except Exception as exc:
                raise GitHubRepositoryError("GitHub hostname resolution failed") from exc

            if not addresses:
                raise GitHubRepositoryError("GitHub hostname returned no IP addresses")

            request = build_pinned_github_request(
                client,
                current_url,
                hostname,
                addresses[0],
            )
            request.headers["User-Agent"] = "DepRisk/1.0"
            if hostname == "api.github.com" and github_token:
                request.headers["Authorization"] = f"Bearer {github_token}"

            try:
                remaining = deadline - asyncio.get_running_loop().time()
                response = await asyncio.wait_for(
                    client.send(
                        request,
                        stream=True,
                        follow_redirects=False,
                    ),
                    timeout=max(remaining, 0.0),
                )
            except (httpx.HTTPError, TimeoutError) as exc:
                raise GitHubRepositoryError("GitHub tarball request failed or timed out") from exc

            try:
                if response.status_code in redirect_statuses:
                    if redirect_count >= max_redirects:
                        raise GitHubRepositoryError("GitHub download exceeded the redirect limit")

                    location = response.headers.get("location")
                    if not location:
                        raise GitHubRepositoryError("GitHub redirect did not include a destination")

                    try:
                        target_url = parsed_url.join(location)
                    except (TypeError, ValueError) as exc:
                        raise GitHubRepositoryError(
                            "GitHub redirect destination is malformed"
                        ) from exc

                    current_url = str(target_url)
                    redirect_count += 1
                    continue

                if response.status_code != 200:
                    raise GitHubRepositoryError(
                        f"GitHub tarball request returned HTTP {response.status_code}"
                    )

                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared_size = int(content_length)
                    except ValueError as exc:
                        raise GitHubRepositoryError(
                            "GitHub returned an invalid content length"
                        ) from exc

                    if declared_size < 0 or declared_size > max_bytes:
                        raise GitHubRepositoryError(
                            "GitHub tarball exceeds the download size limit"
                        )

                chunks: list[bytes] = []
                downloaded_bytes = 0

                try:
                    remaining = deadline - asyncio.get_running_loop().time()
                    async with asyncio.timeout(max(remaining, 0.0)):
                        async for chunk in response.aiter_raw():
                            downloaded_bytes += len(chunk)

                            if downloaded_bytes > max_bytes:
                                raise GitHubRepositoryError(
                                    "GitHub tarball exceeds the download size limit"
                                )

                            chunks.append(chunk)
                except (httpx.HTTPError, TimeoutError) as exc:
                    raise GitHubRepositoryError(
                        "GitHub tarball download was interrupted or timed out"
                    ) from exc

                return b"".join(chunks)
            finally:
                await response.aclose()


@contextmanager
def extract_github_repository_tarball(
    archive: bytes,
    *,
    max_archive_size: int = 100 * 1024 * 1024,
    max_total_size: int = 500 * 1024 * 1024,
    max_file_size: int = 50 * 1024 * 1024,
    max_members: int = 100_000,
    max_depth: int = 32,
    max_path_length: int = 1024,
) -> Iterator[Path]:
    """Safely extract a GitHub tarball into a temporary repository directory."""
    import io
    import re
    import tempfile
    from pathlib import PurePosixPath

    limits = {
        "max_archive_size": max_archive_size,
        "max_total_size": max_total_size,
        "max_file_size": max_file_size,
        "max_members": max_members,
        "max_depth": max_depth,
        "max_path_length": max_path_length,
    }

    for name, value in limits.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise GitHubRepositoryError(f"{name} must be a positive integer")

    if not isinstance(archive, bytes) or not archive:
        raise GitHubRepositoryError("GitHub tarball must be non-empty bytes")

    if len(archive) > max_archive_size:
        raise GitHubRepositoryError("GitHub tarball exceeds the archive size limit")

    temporary_directory = tempfile.TemporaryDirectory(prefix="deprisk-github-")
    extraction_root = Path(temporary_directory.name)

    try:
        total_size = 0
        member_count = 0
        repository_root: str | None = None
        explicit_paths: set[str] = set()
        file_paths: set[str] = set()
        directory_paths: set[str] = set()
        lockfile_found = False

        with tarfile.open(
            fileobj=io.BytesIO(archive),
            mode="r|gz",
        ) as tar:
            for member in tar:
                member_count += 1

                if member_count > max_members:
                    raise GitHubRepositoryError("GitHub archive exceeds the member count limit")

                raw_path = member.name

                if (
                    not raw_path
                    or len(raw_path) > max_path_length
                    or "\x00" in raw_path
                    or "\\" in raw_path
                    or raw_path.startswith("/")
                    or re.match(r"^[A-Za-z]:", raw_path)
                ):
                    raise GitHubRepositoryError("GitHub archive contains an unsafe path")

                is_directory = member.isdir()

                if raw_path.endswith("/"):
                    if not is_directory:
                        raise GitHubRepositoryError("GitHub archive contains an invalid file path")
                    raw_path = raw_path[:-1]

                parts = raw_path.split("/")

                windows_reserved_names = {
                    "CON",
                    "PRN",
                    "AUX",
                    "NUL",
                    *(f"COM{number}" for number in range(1, 10)),
                    *(f"LPT{number}" for number in range(1, 10)),
                    "CONIN$",
                    "CONOUT$",
                }

                if (
                    not parts
                    or any(
                        part in {"", ".", ".."}
                        or any(character in '<>:"|?*' for character in part)
                        or any(ord(character) < 32 for character in part)
                        or part.endswith((" ", "."))
                        or part.split(".", 1)[0].upper() in windows_reserved_names
                        for part in parts
                    )
                    or len(parts) - 1 > max_depth
                ):
                    raise GitHubRepositoryError(
                        "GitHub archive contains an unsafe or non-portable path"
                    )

                pure_path = PurePosixPath(raw_path)

                if pure_path.is_absolute() or pure_path.drive:
                    raise GitHubRepositoryError("GitHub archive contains an absolute path")

                if repository_root is None:
                    repository_root = parts[0]
                elif parts[0].casefold() != repository_root.casefold():
                    raise GitHubRepositoryError("GitHub archive contains multiple repository roots")

                relative_parts = parts[1:]

                if not relative_parts and not is_directory:
                    raise GitHubRepositoryError("GitHub archive root must be a directory")

                normalized_path = "/".join(parts)
                path_key = normalized_path.casefold()

                if path_key in explicit_paths:
                    raise GitHubRepositoryError("GitHub archive contains duplicate paths")

                explicit_paths.add(path_key)

                if is_directory:
                    if member.size != 0:
                        raise GitHubRepositoryError("GitHub archive directory has unexpected data")

                    directory_paths.add(path_key)
                elif member.isreg():
                    if getattr(member, "sparse", None) is not None:
                        raise GitHubRepositoryError("GitHub archive contains a sparse file")

                    if member.size < 0 or member.size > max_file_size:
                        raise GitHubRepositoryError("GitHub archive contains an oversized file")

                    total_size += member.size

                    if total_size > max_total_size:
                        raise GitHubRepositoryError(
                            "GitHub archive exceeds the extracted size limit"
                        )

                    file_paths.add(path_key)
                else:
                    raise GitHubRepositoryError("GitHub archive contains an unsupported file type")

                for index in range(1, len(parts)):
                    parent = "/".join(parts[:index])

                    parent_key = parent.casefold()

                    if parent_key in file_paths:
                        raise GitHubRepositoryError("GitHub archive contains conflicting paths")

                    directory_paths.add(parent_key)

                if path_key in file_paths and path_key in directory_paths:
                    raise GitHubRepositoryError("GitHub archive contains conflicting paths")

                if not relative_parts:
                    continue

                target = extraction_root.joinpath(*relative_parts)

                if is_directory:
                    target.mkdir(parents=True, exist_ok=True)
                    continue

                if parts[-1] == "package-lock.json" and len(relative_parts) != 1:
                    # Nested lockfiles are validated but not extracted.
                    continue

                if parts[-1] == "package-lock.json":
                    if lockfile_found:
                        raise GitHubRepositoryError(
                            "GitHub archive contains multiple package lockfiles"
                        )
                    lockfile_found = True

                target.parent.mkdir(parents=True, exist_ok=True)

                try:
                    source = tar.extractfile(member)
                    if source is None:
                        raise GitHubRepositoryError("GitHub archive contains an unreadable file")

                    remaining = member.size

                    with source, target.open("xb") as destination:
                        while remaining:
                            chunk = source.read(min(1024 * 1024, remaining))

                            if not chunk:
                                raise GitHubRepositoryError(
                                    "GitHub archive contains a truncated file"
                                )

                            destination.write(chunk)
                            remaining -= len(chunk)
                except FileExistsError as exc:
                    raise GitHubRepositoryError(
                        "GitHub archive contains conflicting paths"
                    ) from exc

        if repository_root is None:
            raise GitHubRepositoryError("GitHub archive is empty")

        if not lockfile_found:
            raise GitHubRepositoryError("GitHub archive does not contain a root package-lock.json")

        yield extraction_root

    except (tarfile.TarError, OSError, EOFError) as exc:
        raise GitHubRepositoryError("GitHub archive could not be safely extracted") from exc
    finally:
        temporary_directory.cleanup()


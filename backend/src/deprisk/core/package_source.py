"""Classification of npm package sources."""

from urllib.parse import urlsplit

from deprisk.core.models import PackageSourceType


def classify_package_source(resolved: str | None) -> PackageSourceType:
    """Classify npm package origin conservatively."""

    if not resolved:
        return PackageSourceType.UNKNOWN

    value = resolved.strip()
    if not value:
        return PackageSourceType.UNKNOWN

    lowered = value.lower()

    if lowered.startswith(("git+", "git://", "ssh://")) or lowered.startswith(
        ("github:", "gitlab:", "bitbucket:")
    ):
        return PackageSourceType.GIT

    if lowered.startswith("file:"):
        return PackageSourceType.FILE

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError:
        return PackageSourceType.UNKNOWN

    if scheme in {"http", "https"}:
        default_port = 443 if scheme == "https" else 80

        is_trusted_registry = (
            (hostname or "").lower() == "registry.npmjs.org"
            and username is None
            and password is None
            and port in (None, default_port)
        )

        if is_trusted_registry:
            return PackageSourceType.REGISTRY

        return PackageSourceType.URL

    if scheme:
        return PackageSourceType.URL

    return PackageSourceType.FILE

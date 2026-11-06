import pytest

from deprisk.vulnerability.ttl_cache import TTLCache


def test_returns_cached_value_before_expiration() -> None:
    now = [100.0]
    cache = TTLCache[str, str](ttl_seconds=10, clock=lambda: now[0])
    cache.put("key", "value")

    now[0] = 109.0
    assert cache.get("key") == "value"


def test_expired_value_is_not_returned() -> None:
    now = [100.0]
    cache = TTLCache[str, str](ttl_seconds=10, clock=lambda: now[0])
    cache.put("key", "value")

    now[0] = 110.0
    assert cache.get("key") is None
    assert len(cache) == 0


def test_get_refreshes_lru_order() -> None:
    cache = TTLCache[str, str](max_entries=2)
    cache.put("first", "1")
    cache.put("second", "2")
    assert cache.get("first") == "1"
    cache.put("third", "3")

    assert cache.get("first") == "1"
    assert cache.get("second") is None
    assert cache.get("third") == "3"


def test_put_replaces_existing_value() -> None:
    cache = TTLCache[str, str]()
    cache.put("key", "old")
    cache.put("key", "new")

    assert cache.get("key") == "new"
    assert len(cache) == 1


def test_clear_removes_all_entries() -> None:
    cache = TTLCache[str, str]()
    cache.put("one", "1")
    cache.put("two", "2")
    cache.clear()

    assert len(cache) == 0
    assert cache.get("one") is None


@pytest.mark.parametrize(
    ("ttl_seconds", "max_entries"),
    [(0, 10), (-1, 10), (10, 0), (10, -1)],
)
def test_rejects_invalid_configuration(
    ttl_seconds: float,
    max_entries: int,
) -> None:
    with pytest.raises(ValueError):
        TTLCache[str, str](
            ttl_seconds=ttl_seconds,
            max_entries=max_entries,
        )

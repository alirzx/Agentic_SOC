"""The ambient set: absolute thresholds plus the relative domain rule."""

from __future__ import annotations

from app.normalizer.extract_keys import DOMAIN_UBIQUITY_RATIO, H_HUB, MIN_RATIO_SAMPLE
from app.services.frequency import common_values


def test_absolute_thresholds_still_apply():
    freq = {("host", "build-01"): H_HUB + 1, ("user", "svc"): 51, ("domain", "cdn.example"): 101}

    common = common_values(freq)

    assert common == {"build-01", "svc", "cdn.example"}


def test_tenant_wide_domain_is_ambient_below_the_absolute_threshold():
    """15 alerts where 12 name the tenant's own zone: common, well under 100."""

    freq = {("domain", "attackrange.local"): 12, ("host", "ar-win-dc"): 12}
    common = common_values(freq, total_alerts=15)

    assert "attackrange.local" in common
    assert 12 >= DOMAIN_UBIQUITY_RATIO * 15
    # Hosts keep the absolute bar: one victim server legitimately appears on
    # every alert of a single-host campaign.
    assert "ar-win-dc" not in common


def test_rare_domain_is_not_ambient():
    freq = {("domain", "rare-vendor.example"): 2, ("domain", "attackrange.local"): 12}

    common = common_values(freq, total_alerts=15)

    assert common == {"attackrange.local"}


def test_ratio_needs_a_window_big_enough_to_mean_anything():
    freq = {("domain", "attackrange.local"): 2}

    assert common_values(freq, total_alerts=MIN_RATIO_SAMPLE - 1) == frozenset()
    assert "attackrange.local" in common_values(freq, total_alerts=MIN_RATIO_SAMPLE)

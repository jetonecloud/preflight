"""Prices and the arithmetic on top of them.

Two things matter here. The numbers have to be right, and when they can't
be known the answer has to be "no figure" rather than a plausible-looking
guess — a wrong dollar amount in a report is worse than a missing one.
"""

from __future__ import annotations

import json

import pytest
from botocore.exceptions import ClientError

from preflight.core.findings import HOURS_PER_MONTH
from preflight.core.pricing import (
    EBS_FALLBACK,
    EBS_GB_MONTH,
    LOAD_BALANCER_HOUR,
    NAT_GATEWAY_HOUR,
    PUBLIC_IPV4_HOUR,
    RDS_SNAPSHOT_GB_MONTH,
    SNAPSHOT_FILL_RATIO,
    SNAPSHOT_GB_MONTH,
    Price,
    PriceBook,
    ebs_monthly,
    one_size_down,
    rds_storage_monthly,
    snapshot_monthly,
)


def test_hourly_prices_are_monthly_at_730_hours():
    assert NAT_GATEWAY_HOUR.monthly() == pytest.approx(0.045 * 730)
    assert PUBLIC_IPV4_HOUR.monthly() == pytest.approx(3.65)
    assert LOAD_BALANCER_HOUR["application"].monthly() == pytest.approx(16.425)


def test_monthly_prices_are_per_unit():
    assert EBS_GB_MONTH["gp3"].monthly(100) == pytest.approx(8.0)
    assert EBS_GB_MONTH["gp2"].monthly(100) == pytest.approx(10.0)


def test_a_derivation_reads_like_arithmetic():
    monthly, basis = ebs_monthly("gp3", 250)
    assert monthly == pytest.approx(20.0)
    assert "250" in basis and "gp3" in basis and "$0.08" in basis
    assert "us-east-1" in basis


def test_an_unknown_volume_type_uses_the_cheapest_tier():
    """Unfamiliar types can only ever understate an estimate."""
    monthly, basis = ebs_monthly("gp-future", 100)
    assert monthly == pytest.approx(EBS_FALLBACK.amount * 100)
    assert "cheapest" in basis


def test_snapshots_are_discounted_for_being_incremental():
    monthly, basis = snapshot_monthly(300)
    assert monthly == pytest.approx(300 * SNAPSHOT_FILL_RATIO * SNAPSHOT_GB_MONTH.amount)
    assert "33%" in basis
    assert monthly < SNAPSHOT_GB_MONTH.monthly(300)


def test_rds_storage_falls_back_to_its_own_cheapest_tier():
    known, _ = rds_storage_monthly("gp2", 100)
    unknown, basis = rds_storage_monthly("something-new", 100)
    assert known == pytest.approx(11.5)
    assert unknown <= known
    assert "cheapest" in basis


def test_rds_snapshot_rate_is_the_backup_rate():
    assert RDS_SNAPSHOT_GB_MONTH.unit == "GB-month"
    assert RDS_SNAPSHOT_GB_MONTH.amount == pytest.approx(0.095)


@pytest.mark.parametrize(
    "instance_type, expected",
    [
        ("m5.xlarge", "m5.large"),
        ("m5.large", "m5.medium"),
        ("t3.nano", None),
        ("c6i.24xlarge", "c6i.18xlarge"),  # the next rung; whether it exists is a pricing question
        ("nonsense", None),
        ("m5", None),
        ("m5.enormous", None),
    ],
)
def test_one_size_down(instance_type, expected):
    assert one_size_down(instance_type) == expected


def test_a_price_describes_itself_with_its_source():
    price = Price(0.05, "GB-month", "a note")
    assert "a note" in price.describe(10, "GB of something")
    assert "10" in price.describe(10, "GB of something")


# --- the pricing API ------------------------------------------------------


def product(rate: str, unit: str = "Hrs") -> str:
    return json.dumps(
        {
            "terms": {
                "OnDemand": {
                    "ABC.JRTCKXETXF": {
                        "priceDimensions": {
                            "ABC.JRTCKXETXF.6YS6EN2CT7": {
                                "unit": unit,
                                "pricePerUnit": {"USD": rate},
                            }
                        }
                    }
                }
            }
        }
    )


class FakePricing:
    def __init__(self, answer):
        self.answer = answer
        self.calls = 0

    def get_products(self, **params):
        self.calls += 1
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


def test_the_api_price_wins_over_the_table():
    client = FakePricing({"PriceList": [product("0.5000")]})
    book = PriceBook(lambda: client)
    assert book.hourly("eu-west-2", "m5.large") == pytest.approx(0.5)
    assert book.used_api


def test_the_cheapest_rate_is_taken_and_zero_rows_ignored():
    client = FakePricing({"PriceList": [product("0.0000"), product("0.3000"), product("0.2000")]})
    assert PriceBook(lambda: client).hourly("us-east-1", "m5.large") == pytest.approx(0.2)


def test_non_hourly_dimensions_are_ignored():
    client = FakePricing({"PriceList": [product("4.0000", unit="Quantity")]})
    # Nothing usable from the API, so the built-in table answers instead.
    assert PriceBook(lambda: client).hourly("us-east-1", "m5.large") == pytest.approx(0.096)


def test_a_denied_pricing_call_falls_back_to_the_table_and_says_so():
    denied = ClientError({"Error": {"Code": "AccessDeniedException"}}, "GetProducts")
    book = PriceBook(lambda: FakePricing(denied))
    assert book.hourly("us-east-1", "m5.large") == pytest.approx(0.096)
    assert not book.used_api
    assert book.degraded_reason


def test_a_failed_api_is_not_retried_for_every_instance():
    denied = ClientError({"Error": {"Code": "AccessDeniedException"}}, "GetProducts")
    client = FakePricing(denied)
    book = PriceBook(lambda: client)
    book.hourly("us-east-1", "m5.large")
    book.hourly("us-east-1", "m5.xlarge")
    assert client.calls == 1


def test_an_unknown_type_with_no_api_has_no_price():
    assert PriceBook().hourly("us-east-1", "x9z.4xlarge") is None


def test_results_are_cached_per_region_and_type():
    client = FakePricing({"PriceList": [product("0.5000")]})
    book = PriceBook(lambda: client)
    book.hourly("us-east-1", "m5.large")
    book.hourly("us-east-1", "m5.large")
    assert client.calls == 1


def test_a_malformed_payload_is_not_a_price():
    client = FakePricing({"PriceList": ["{not json", json.dumps({"terms": {}})]})
    # Falls through to the table rather than raising.
    assert PriceBook(lambda: client).hourly("us-east-1", "m5.large") == pytest.approx(0.096)


def test_hours_per_month_is_the_aws_average():
    assert HOURS_PER_MONTH == 730

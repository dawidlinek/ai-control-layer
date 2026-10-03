from src.payments_cli import total_cents


def test_total_cents_exact() -> None:
    rows = [{"amount": "0.10"}, {"amount": "0.20"}, {"amount": "19.99"}]
    assert total_cents(rows) == 2029

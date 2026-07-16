#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import random
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Callable

import sentry_sdk


SERVICES = [
    "checkout",
    "payments",
    "catalog",
    "users",
    "notifications",
    "reports",
]

TRANSACTIONS = [
    "GET /api/v1/products",
    "GET /api/v1/users/{id}",
    "POST /api/v1/orders",
    "POST /api/v1/payments",
    "GET /api/v1/reports",
    "PUT /api/v1/profile",
]

SPAN_OPERATIONS = [
    ("db.sql.query", "SELECT * FROM users WHERE id = %s"),
    ("db.sql.query", "SELECT * FROM products WHERE category_id = %s"),
    ("db.sql.query", "INSERT INTO orders (...) VALUES (...)"),
    ("cache.get", "redis GET session:{session_id}"),
    ("cache.set", "redis SET cart:{user_id}"),
    ("http.client", "GET http://catalog-service/api/products"),
    ("http.client", "POST http://payment-service/api/charge"),
    ("queue.publish", "publish order.created"),
    ("queue.process", "consume notification.send"),
    ("template.render", "render checkout.html"),
    ("function", "calculate_order_total"),
    ("serialization", "serialize API response"),
]

LOG_MESSAGES = {
    "debug": [
        "Cache lookup completed",
        "Request payload validated",
        "Feature flag evaluated",
    ],
    "info": [
        "Order processing started",
        "User authenticated successfully",
        "Background job completed",
        "Payment request submitted",
    ],
    "warning": [
        "Database query exceeded expected duration",
        "Retrying upstream service request",
        "Cache miss rate is elevated",
        "Queue consumer is falling behind",
    ],
    "error": [
        "Upstream service returned an error",
        "Unable to persist application state",
        "Payment provider request failed",
        "Background task execution failed",
    ],
    "critical": [
        "Database connection pool exhausted",
        "Critical dependency unavailable",
    ],
}


class PilotDatabaseError(RuntimeError):
    pass


class PilotPaymentError(RuntimeError):
    pass


class PilotValidationError(ValueError):
    pass


class PilotIntegrationError(ConnectionError):
    pass


ISSUE_FACTORIES: list[Callable[[int], Exception]] = [
    lambda number: PilotDatabaseError(
        f"Database connection failed for shard {number % 3}"
    ),
    lambda number: PilotPaymentError(
        f"Payment provider rejected test transaction: code={400 + number % 10}"
    ),
    lambda number: PilotValidationError(
        f"Invalid pilot request field: field_{number % 5}"
    ),
    lambda number: PilotIntegrationError(
        f"Inventory service timeout in region-{number % 4}"
    ),
]


@dataclass
class GeneratorConfig:
    transactions: int
    depth: int
    children: int
    issues: int
    logs: int
    delay: float
    environment: str
    release: str
    unique_issues: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate GlitchTip pilot telemetry."
    )

    parser.add_argument(
        "--dsn",
        required=True,
        help="GlitchTip project DSN",
    )
    parser.add_argument(
        "--transactions",
        type=int,
        default=100,
        help="Number of transactions, default: 100",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=4,
        help="Span tree depth, default: 4",
    )
    parser.add_argument(
        "--children",
        type=int,
        default=3,
        help="Children per span level, default: 3",
    )
    parser.add_argument(
        "--issues",
        type=int,
        default=30,
        help="Number of error events, default: 30",
    )
    parser.add_argument(
        "--logs",
        type=int,
        default=200,
        help="Number of structured logs, default: 200",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.01,
        help="Delay between operations in seconds, default: 0.01",
    )
    parser.add_argument(
        "--environment",
        default="pilot",
    )
    parser.add_argument(
        "--release",
        default="telemetry-generator@1.0.0",
    )
    parser.add_argument(
        "--unique-issues",
        action="store_true",
        help="Generate mostly separate issue groups",
    )
    parser.add_argument(
        "--debug-sdk",
        action="store_true",
        help="Enable Sentry SDK debug output",
    )

    return parser.parse_args()


def configure_sdk(args: argparse.Namespace) -> None:
    sentry_sdk.init(
        dsn=args.dsn,
        environment=args.environment,
        release=args.release,
        traces_sample_rate=1.0,
        enable_logs=True,
        debug=args.debug_sdk,
        send_default_pii=False,
        max_breadcrumbs=100,
    )


def make_span_tree(
    depth: int,
    children: int,
    delay: float,
    transaction_number: int,
) -> None:
    if depth <= 0:
        return

    for child_number in range(children):
        operation, description = random.choice(SPAN_OPERATIONS)

        with sentry_sdk.start_span(
            op=operation,
            name=description,
        ) as span:
            span.set_data("pilot.depth", depth)
            span.set_data("pilot.child", child_number)
            span.set_data("pilot.transaction", transaction_number)
            span.set_data(
                "db.rows_affected",
                random.randint(0, 500),
            )

            time.sleep(
                random.uniform(
                    max(delay / 2, 0),
                    max(delay * 2, 0.001),
                )
            )

            make_span_tree(
                depth=depth - 1,
                children=children,
                delay=delay,
                transaction_number=transaction_number,
            )


def generate_transactions(config: GeneratorConfig) -> None:
    print(f"Generating {config.transactions} transactions...")

    for number in range(config.transactions):
        transaction_name = random.choice(TRANSACTIONS)
        service = random.choice(SERVICES)
        user_id = random.randint(1, 500)

        with sentry_sdk.isolation_scope() as scope:
            scope.set_user(
                {
                    "id": str(user_id),
                    "username": f"pilot-user-{user_id}",
                }
            )
            scope.set_tag("pilot", "true")
            scope.set_tag("service", service)
            scope.set_tag("region", f"region-{number % 4}")
            scope.set_tag(
                "transaction.variant",
                f"variant-{number % 8}",
            )
            scope.set_context(
                "pilot",
                {
                    "generator_run": config.release,
                    "sequence": number,
                    "service": service,
                },
            )

            with sentry_sdk.start_transaction(
                op="http.server",
                name=transaction_name,
            ) as transaction:
                transaction.set_data(
                    "http.request.method",
                    transaction_name.split(" ", 1)[0],
                )
                transaction.set_data(
                    "http.response.status_code",
                    random.choice([200, 200, 200, 201, 204, 400, 500]),
                )
                transaction.set_data(
                    "pilot.transaction_number",
                    number,
                )

                sentry_sdk.add_breadcrumb(
                    category="request",
                    message="Pilot request accepted",
                    level="info",
                    data={
                        "transaction_number": number,
                        "service": service,
                    },
                )

                make_span_tree(
                    depth=config.depth,
                    children=config.children,
                    delay=config.delay,
                    transaction_number=number,
                )

        if (number + 1) % 10 == 0:
            print(f"  transactions: {number + 1}/{config.transactions}")


def raise_pilot_exception(
    issue_number: int,
    unique: bool,
) -> None:
    factory = ISSUE_FACTORIES[issue_number % len(ISSUE_FACTORIES)]
    exception = factory(issue_number)

    if unique:
        raise type(exception)(
            f"{exception}; unique_event={uuid.uuid4()}"
        )

    raise exception


def generate_issues(config: GeneratorConfig) -> None:
    print(f"Generating {config.issues} issue events...")

    for number in range(config.issues):
        service = random.choice(SERVICES)

        with sentry_sdk.isolation_scope() as scope:
            scope.set_tag("pilot", "true")
            scope.set_tag("service", service)
            scope.set_tag("issue.number", str(number))
            scope.set_level(
                random.choice(["error", "error", "warning", "fatal"])
            )
            scope.set_user(
                {
                    "id": str(number % 50),
                    "username": f"issue-user-{number % 50}",
                }
            )

            sentry_sdk.add_breadcrumb(
                category="pilot.action",
                message="Starting operation that may fail",
                level="info",
                data={"issue_number": number},
            )

            sentry_sdk.add_breadcrumb(
                category="db.query",
                message="SELECT pilot data",
                level="debug",
                data={
                    "duration_ms": random.randint(10, 900),
                    "rows": random.randint(0, 1000),
                },
            )

            try:
                with sentry_sdk.start_transaction(
                    op="task",
                    name=f"pilot.issue.{number % 5}",
                ):
                    with sentry_sdk.start_span(
                        op="function",
                        name="execute failure scenario",
                    ):
                        time.sleep(config.delay)
                        raise_pilot_exception(
                            issue_number=number,
                            unique=config.unique_issues,
                        )
            except Exception:
                sentry_sdk.capture_exception()

        if (number + 1) % 10 == 0:
            print(f"  issues: {number + 1}/{config.issues}")


def generate_logs(config: GeneratorConfig) -> None:
    print(f"Generating {config.logs} structured logs...")

    sdk_logger = sentry_sdk.logger

    levels = [
        "debug",
        "info",
        "info",
        "info",
        "warning",
        "warning",
        "error",
        "critical",
    ]

    for number in range(config.logs):
        level = random.choice(levels)
        message = random.choice(LOG_MESSAGES[level])
        service = random.choice(SERVICES)

        attributes = {
            "pilot": True,
            "pilot.sequence": number,
            "service.name": service,
            "deployment.environment": config.environment,
            "region": f"region-{number % 4}",
            "user.id": str(number % 100),
            "http.status_code": random.choice(
                [200, 201, 204, 400, 401, 404, 429, 500, 503]
            ),
            "duration_ms": random.randint(1, 5000),
        }

        log_method = getattr(sdk_logger, level)
        log_method(message, attributes=attributes)

        if (number + 1) % 50 == 0:
            print(f"  logs: {number + 1}/{config.logs}")


def print_estimate(config: GeneratorConfig) -> None:
    if config.children == 1:
        spans_per_transaction = config.depth
    else:
        spans_per_transaction = sum(
            config.children**level
            for level in range(1, config.depth + 1)
        )

    total_spans = spans_per_transaction * config.transactions

    print()
    print("Estimated telemetry:")
    print(f"  transactions : {config.transactions}")
    print(f"  spans/tx     : {spans_per_transaction}")
    print(f"  total spans  : {total_spans}")
    print(f"  issue events : {config.issues}")
    print(f"  logs         : {config.logs}")
    print()


def main() -> int:
    args = parse_args()

    if args.depth < 1:
        raise ValueError("--depth must be at least 1")
    if args.children < 1:
        raise ValueError("--children must be at least 1")

    config = GeneratorConfig(
        transactions=args.transactions,
        depth=args.depth,
        children=args.children,
        issues=args.issues,
        logs=args.logs,
        delay=args.delay,
        environment=args.environment,
        release=args.release,
        unique_issues=args.unique_issues,
    )

    print_estimate(config)
    configure_sdk(args)

    try:
        generate_transactions(config)
        generate_issues(config)
        generate_logs(config)
    finally:
        print("Flushing SDK queue...")
        sentry_sdk.flush(timeout=30)

    print("Done.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sentry_sdk.flush(timeout=10)
        sys.exit(130)

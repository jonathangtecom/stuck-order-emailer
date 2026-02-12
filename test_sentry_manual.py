"""Manual test script to verify Sentry captures errors correctly.

Run with: python3 test_sentry_manual.py

This will trigger a test error that should appear in Sentry dashboard.
"""
import os
import sentry_sdk


def main():
    """Run manual Sentry verification test."""
    # Load .env file
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        print("Warning: python-dotenv not installed, relying on existing environment variables")

    SENTRY_DSN = os.environ.get('SENTRY_DSN', '')

    if not SENTRY_DSN:
        print("ERROR: SENTRY_DSN not configured in .env")
        print("Add your Sentry DSN to .env and try again.")
        exit(1)

    # Initialize Sentry
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        environment=os.environ.get('SENTRY_ENVIRONMENT', 'test'),
        traces_sample_rate=0.0,
    )

    print(f"Sentry initialized with environment: {os.environ.get('SENTRY_ENVIRONMENT', 'test')}")
    print("Triggering test error...")

    # Trigger a test error
    try:
        sentry_sdk.set_tag('test_type', 'manual_verification')
        sentry_sdk.set_context('test', {
            'purpose': 'Verify Sentry integration',
            'expected': 'This error should appear in Sentry dashboard',
        })

        raise ValueError("Test error from stuck-order-emailer - Sentry integration verified!")
    except Exception as e:
        sentry_sdk.capture_exception(e)
        print(f"Exception captured: {e}")

    print("Test error sent to Sentry.")
    print("Check your Sentry dashboard at https://sentry.io")
    print("You should see a ValueError with tags: test_type=manual_verification")


if __name__ == "__main__":
    main()

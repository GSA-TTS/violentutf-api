"""Email utility functions for sending notifications."""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


async def send_email(
    to_email: str | List[str],
    subject: str,
    body: str,
    is_html: bool = False,
    from_email: Optional[str] = None,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
) -> bool:
    """Send an email notification.

    Args:
        to_email: Recipient email address(es)
        subject: Email subject
        body: Email body content
        is_html: Whether body is HTML content
        from_email: Sender email (uses default if not provided)
        cc: CC recipients
        bcc: BCC recipients

    Returns:
        Success status
    """
    try:
        # Check if email is configured
        if not hasattr(settings, "SMTP_HOST") or not settings.SMTP_HOST:
            logger.warning("Email not configured, skipping email send")
            return False

        # Default sender
        if not from_email:
            from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@violentutf.local")

        # Ensure to_email is a list
        if isinstance(to_email, str):
            to_email = [to_email]

        # Create message
        msg = MIMEMultipart("alternative" if is_html else "mixed")
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = ", ".join(to_email)

        if cc:
            msg["Cc"] = ", ".join(cc)
        if bcc:
            msg["Bcc"] = ", ".join(bcc)

        # Add body
        mime_type = "html" if is_html else "plain"
        msg.attach(MIMEText(body, mime_type))

        # Connect to SMTP server
        smtp_host = settings.SMTP_HOST
        smtp_port = getattr(settings, "SMTP_PORT", 587)
        smtp_user = getattr(settings, "SMTP_USER", None)
        smtp_password = getattr(settings, "SMTP_PASSWORD", None)
        smtp_use_tls = getattr(settings, "SMTP_USE_TLS", True)

        # Send email
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if smtp_use_tls:
                server.starttls()

            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)

            # Combine all recipients
            all_recipients = to_email + (cc or []) + (bcc or [])
            server.send_message(msg, from_email, all_recipients)

        logger.info(f"Email sent successfully to {', '.join(to_email)}")
        return True

    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False


async def send_report_notification(
    recipients: List[str], report_name: str, report_id: str, download_url: str, period_days: int = 30
) -> bool:
    """Send a report notification email.

    Args:
        recipients: List of recipient email addresses
        report_name: Name of the report
        report_id: Report ID
        download_url: URL to download the report
        period_days: Reporting period in days

    Returns:
        Success status
    """
    subject = f"Report Available: {report_name}"

    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2 style="color: #667eea;">Architectural Metrics Report Available</h2>

        <p>Your scheduled report <strong>{report_name}</strong> has been generated successfully.</p>

        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <h3 style="color: #333; margin-top: 0;">Report Details:</h3>
            <ul style="list-style-type: none; padding: 0;">
                <li>📊 <strong>Report ID:</strong> {report_id}</li>
                <li>📅 <strong>Period:</strong> Last {period_days} days</li>
                <li>🕐 <strong>Generated:</strong> Just now</li>
            </ul>
        </div>

        <div style="margin: 30px 0;">
            <a href="{download_url}" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Download Report
            </a>
        </div>

        <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">

        <p style="color: #666; font-size: 0.9em;">
            This is an automated notification from the Architectural Audit System.<br>
            If you have questions, please contact your system administrator.
        </p>
    </body>
    </html>
    """

    return await send_email(to_email=recipients, subject=subject, body=body, is_html=True)


async def send_failure_notification(recipients: List[str], report_name: str, error_message: str) -> bool:
    """Send a failure notification email.

    Args:
        recipients: List of recipient email addresses
        report_name: Name of the report
        error_message: Error message

    Returns:
        Success status
    """
    subject = f"Report Generation Failed: {report_name}"

    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2 style="color: #dc3545;">Report Generation Failed</h2>

        <p>The scheduled report <strong>{report_name}</strong> failed to generate.</p>

        <div style="background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <h3 style="margin-top: 0;">Error Details:</h3>
            <p style="margin: 0; font-family: monospace;">{error_message}</p>
        </div>

        <p>Please contact your system administrator for assistance.</p>

        <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">

        <p style="color: #666; font-size: 0.9em;">
            This is an automated notification from the Architectural Audit System.
        </p>
    </body>
    </html>
    """

    return await send_email(to_email=recipients, subject=subject, body=body, is_html=True)

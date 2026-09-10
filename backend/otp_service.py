import os
import smtplib

from email.mime.text import MIMEText
from dotenv import load_dotenv
from twilio.rest import Client


load_dotenv()


EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")


def send_email_otp(email, otp):

    message = MIMEText(
        f"""
Your verification OTP is:

{otp}

This OTP will expire in 5 minutes.

If you did not request this OTP, ignore this email.
"""
    )

    message["Subject"] = "Security Platform OTP Verification"
    message["From"] = EMAIL_ADDRESS
    message["To"] = email

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465
    ) as server:

        server.login(
            EMAIL_ADDRESS,
            EMAIL_APP_PASSWORD
        )

        server.send_message(message)


def send_sms_otp(mobile, otp):

    client = Client(
        TWILIO_ACCOUNT_SID,
        TWILIO_AUTH_TOKEN
    )

    client.messages.create(
        body=f"Your verification OTP is {otp}. Valid for 5 minutes.",
        from_=TWILIO_PHONE_NUMBER,
        to=mobile
    )
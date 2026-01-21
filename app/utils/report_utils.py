import io
import csv
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from app.database import get_db
from app.validators import ReportPeriod
from app.config import settings

def generate_csv_report(user_email: str, period: ReportPeriod):
    """
    Fetches data based on the validated ReportPeriod enum.
    """
    db = get_db()
    collection = db["expense"]
    
    # Map the Enum members directly to day counts
    periods_map = {
        ReportPeriod.THIRTY_DAYS: 30,
        ReportPeriod.QUARTER: 90,
        ReportPeriod.HALFYEAR: 182,
        ReportPeriod.YEAR: 365
    }
    
    days = periods_map[period]
    start_date = datetime.now() - timedelta(days=days)
    end_date = datetime.now() + timedelta(days=1)
    
    query = {
        "email": user_email,
        "date": {"$gte": start_date, "$le":end_date} 
    }
    
    
    projection = {"_id": 0, "description": 0, "email": 0}
    data = list(collection.find(query, projection))

    if not data:
        return None

    with io.StringIO() as output:
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()
    

def send_report_via_smtp(recipient_email, csv_content,period_label):
    
    # --- Configuration ---
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SENDER_EMAIL = settings.mail
    SENDER_PASSWORD = settings.mail_password

    # 1. Create the Email Container
    msg = EmailMessage()
    msg['Subject'] = f"Your Expense Report - {period_label.capitalize()}"
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email
    msg.set_content(f"Hello,\n\nPlease find your expense report for the period: {period_label}.\n\nRegards,\nExpense Tracker Team")

    # 2. Add the CSV Attachment
    # We encode the string to bytes for the email protocol
    msg.add_attachment(
        csv_content.encode('utf-8'),
        maintype='text',
        subtype='csv',
        filename=f"report_{period_label}.csv"
    )

    # 3. Send the Email
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()  # Secure the connection
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
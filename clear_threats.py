
from app import app
from Database.database import db
from Database.models import ThreatEvent, Alert, LogEntry, Report

with app.app_context():

    # Delete alerts first because they reference threat_events
    Alert.query.delete()

    # Delete detected threats
    ThreatEvent.query.delete()

    # Delete previously uploaded/processed logs
    LogEntry.query.delete()

    # Delete generated reports
    Report.query.delete()

    db.session.commit()

    print("=" * 50)
    print("OLD PROJECT DATA CLEARED")
    print("=" * 50)
    print("Threats  : 0")
    print("Alerts   : 0")
    print("Logs     : 0")
    print("Reports  : 0")
    print("=" * 50)


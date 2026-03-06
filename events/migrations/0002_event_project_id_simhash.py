# events/migrations/0002_event_project_id_simhash.py
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("events", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="event",
            name="project_id",
            field=models.CharField(
                blank=True,
                db_index=True,
                max_length=128,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="event",
            name="simhash",
            field=models.BigIntegerField(
                blank=True,
                db_index=True,
                null=True,
                help_text="64-bit SimHash fingerprint stored as signed int (two's complement).",
            ),
        ),
    ]
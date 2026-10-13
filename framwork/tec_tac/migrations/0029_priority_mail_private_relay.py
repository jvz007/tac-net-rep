from django.db import migrations, models


class Migration(migrations.Migration):
    """The private mail relay switch for Core's own Priority 1 email, as a runtime setting (1.17.26, AD-30).

    Additive: one boolean column, default off. The existing row reads off, so nothing changes until a superuser turns it on."""

    dependencies = [
        ("tec_tac", "0028_session_theme"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacruntimeconfig",
            name="priority_mail_private_relay",
            field=models.BooleanField(default=False),
        ),
    ]

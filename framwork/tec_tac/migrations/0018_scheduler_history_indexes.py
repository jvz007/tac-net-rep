from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0017_session_history_cleanup_schedule")]

    operations = [
        migrations.AddIndex(
            model_name="tectacschedulerun",
            index=models.Index(fields=["status", "-created_at"], name="tectac_run_hist_status_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacschedulerun",
            index=models.Index(fields=["action_id", "-created_at"], name="tectac_run_hist_action_idx"),
        ),
    ]

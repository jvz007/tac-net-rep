from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("tfdreporting", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="ExtensionRolePermission",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("role_id", models.PositiveIntegerField()),
                ("codename", models.CharField(max_length=150)),
                ("granted", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["role_id", "codename"]},
        ),
        migrations.AddConstraint(
            model_name="extensionrolepermission",
            constraint=models.UniqueConstraint(fields=("role_id", "codename"), name="tfd_unique_role_permission"),
        ),
        migrations.AddIndex(
            model_name="extensionrolepermission",
            index=models.Index(fields=["role_id", "codename"], name="tfd_role_perm_lookup"),
        ),
    ]

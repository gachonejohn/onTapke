# Generated by Django 5.2 on 2025-04-14 14:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_alter_customuser_email_alter_customuser_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='email_hash',
            field=models.CharField(db_index=True, default=1, editable=False, max_length=64, unique=True),
            preserve_default=False,
        ),
    ]

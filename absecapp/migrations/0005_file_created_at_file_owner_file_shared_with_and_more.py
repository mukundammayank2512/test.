# Generated by Django 5.1.4 on 2024-12-17 06:44

import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('absecapp', '0004_customuser_phone'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='file',
            name='owner',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='file',
            name='shared_with',
            field=models.ManyToManyField(blank=True, related_name='shared_files', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='file',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.CreateModel(
            name='ShareableLink',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.UUIDField(default=uuid.uuid4, unique=True)),
                ('expires_at', models.DateTimeField()),
                ('file', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='absecapp.file')),
            ],
        ),
    ]
import django.db.models.deletion
from django.db import migrations, models


def copy_existing_pages(apps, schema_editor):
    Workspace = apps.get_model('webapp', 'Workspace')
    StatusPage = apps.get_model('webapp', 'StatusPage')
    alias = schema_editor.connection.alias
    for workspace in Workspace.objects.using(alias).all().iterator():
        StatusPage.objects.using(alias).create(
            workspace_id=workspace.pk, legacy_primary=True,
            public_enabled=workspace.public_enabled, public_slug=workspace.public_slug,
            public_token_hash=workspace.public_token_hash, public_domains=workspace.public_domains,
        )


class Migration(migrations.Migration):
    dependencies = [('webapp', '0005_workspace_public_slug')]
    operations = [
        migrations.CreateModel(
            name='StatusPage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False,
                                           verbose_name='ID')),
                ('title', models.CharField(blank=True, default='', max_length=120)),
                ('access_mode', models.CharField(default='public', max_length=7,
                    choices=[('public', 'Public'), ('private', 'Private link')])),
                ('public_enabled', models.BooleanField(default=True)),
                ('public_domains', models.JSONField(default=list)),
                ('public_slug', models.CharField(max_length=64, unique=True)),
                ('public_token_hash', models.CharField(blank=True, db_index=True, default='', max_length=64)),
                ('legacy_primary', models.BooleanField(default=False)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('workspace', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                    related_name='status_pages', to='webapp.workspace')),
            ],
            options={'ordering': ['pk']},
        ),
        migrations.AddConstraint(model_name='statuspage', constraint=models.UniqueConstraint(
            fields=('workspace',), condition=models.Q(legacy_primary=True),
            name='status_page_legacy_primary')),
        migrations.AddConstraint(model_name='statuspage', constraint=models.CheckConstraint(
            condition=models.Q(access_mode__in=['public', 'private']),
            name='status_page_valid_access')),
        migrations.RunPython(copy_existing_pages, migrations.RunPython.noop),
    ]

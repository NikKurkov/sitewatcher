import secrets

from django.db import migrations, models


def assign_paths(apps, schema_editor):
    Workspace = apps.get_model('webapp', 'Workspace')
    for index, workspace in enumerate(Workspace.objects.using(schema_editor.connection.alias)
                                      .order_by('pk')):
        workspace.public_slug = 'status' if index == 0 else 'status-' + secrets.token_hex(8)
        workspace.save(update_fields=['public_slug'])


class Migration(migrations.Migration):
    dependencies = [('webapp', '0004_workspace_domain_order')]
    operations = [
        migrations.AddField(
            model_name='workspace', name='public_slug',
            field=models.CharField(max_length=64, unique=True, null=True, blank=True),
        ),
        migrations.RunPython(assign_paths, migrations.RunPython.noop),
    ]

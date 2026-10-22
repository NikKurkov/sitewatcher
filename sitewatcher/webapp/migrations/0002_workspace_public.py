from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('webapp', '0001_initial')]
    operations = [
        migrations.AddField(model_name='workspace', name='public_enabled',
                            field=models.BooleanField(default=False)),
        migrations.AddField(model_name='workspace', name='public_token_hash',
                            field=models.CharField(blank=True, db_index=True, default='', max_length=64)),
        migrations.AddField(model_name='workspace', name='public_domains',
                            field=models.JSONField(default=list)),
    ]

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('webapp', '0007_statuspage_private_token_nonce')]

    operations = [migrations.AddField(
        model_name='statuspage', name='public_groups', field=models.JSONField(default=list),
    )]

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('webapp', '0003_workspace_language')]
    operations = [migrations.AddField(
        model_name='workspace', name='domain_order', field=models.JSONField(default=list),
    )]

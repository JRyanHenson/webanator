# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2018-02-06 22:02
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('poam', '0002_auto_20171219_1053'),
    ]

    operations = [
        migrations.CreateModel(
            name='Document',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.CharField(blank=True, max_length=255)),
                ('document', models.FileField(upload_to='documents/')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='VulnId',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('vuln_id', models.CharField(max_length=8, unique=True)),
            ],
            options={
                'db_table': 'vuln_id',
            },
        ),
        migrations.RemoveIndex(
            model_name='weakness',
            name='weakness_vuln_id_df0476_idx',
        ),
        migrations.AddField(
            model_name='device',
            name='os',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='credentialed_scan',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='cvss_base_score',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='cvss_temporal_score',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='cvss_temporal_vector',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='cvss_vector',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='exploit_available',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='plugin_family',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='plugin_output',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='synopsis',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='check_contents',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='comments',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='fix_text',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='milestone_changes',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='mitigated_severity',
            field=models.CharField(blank=True, max_length=4, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='mitigation',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='raw_severity',
            field=models.CharField(max_length=8),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='resources_required',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='scheduled_completion_date',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='status',
            field=models.CharField(max_length=32),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='vuln_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='Weaknesses', to='poam.VulnId'),
        ),
        migrations.AlterUniqueTogether(
            name='device',
            unique_together=set([('name', 'system')]),
        ),
        migrations.AddIndex(
            model_name='weakness',
            index=models.Index(fields=['vuln_id'], name='weakness_vuln_id_c7d5f9_idx'),
        ),
    ]

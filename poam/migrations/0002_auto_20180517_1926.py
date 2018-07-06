# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2018-05-18 01:26
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('poam', '0001_initial'),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name='weakness',
            name='weakness_vuln_id_c7d5f9_idx',
        ),
        migrations.RemoveField(
            model_name='device',
            name='cpe',
        ),
        migrations.RemoveField(
            model_name='device',
            name='software',
        ),
        migrations.RemoveField(
            model_name='weakness',
            name='cpe',
        ),
        migrations.AddField(
            model_name='device',
            name='cpes',
            field=models.ManyToManyField(blank=True, to='poam.CPE'),
        ),
        migrations.AddField(
            model_name='device',
            name='type',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='finding_details',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='weakness',
            name='stig_ref',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='cci',
            name='cci',
            field=models.CharField(max_length=32),
        ),
        migrations.AlterField(
            model_name='device',
            name='mac',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='device',
            name='os',
            field=models.CharField(blank=True, max_length=256, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='devices',
            field=models.ManyToManyField(to='poam.Device'),
        ),
        migrations.RemoveField(
            model_name='weakness',
            name='security_control',
        ),
        migrations.AddField(
            model_name='weakness',
            name='security_control',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='weakness',
            name='vuln_id',
            field=models.CharField(default='', max_length=8),
            preserve_default=False,
        ),
        migrations.AddIndex(
            model_name='weakness',
            index=models.Index(fields=['vuln_id'], name='weakness_vuln_id_df0476_idx'),
        ),
        migrations.DeleteModel(
            name='VulnId',
        ),
    ]
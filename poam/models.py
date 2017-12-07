from django.db import models


# Create your models here.
class SecurityControl(models.Model):
	description = models.TextField()
	title = models.CharField(max_length=256)

	class Meta:
		db_table = 'security_control'


class PointOfContact(models.Model):
	name = models.CharField(max_length=64)
	email = models.EmailField(max_length=256)
	phone = models.CharField(max_length=16)

	def __str__(self):
		return self.name

	class Meta:
		db_table = 'point_of_contact'

	def get_weaknesses(self):
		'''Get weaknesses for a specific POC'''
		return self.weaknesses.all()

	def get_systems(self):
		'''Get systems for a specific POC'''
		return self.systems.all()


class System(models.Model):
	name = models.CharField(max_length=256)
	update_date = models.DateTimeField(auto_now=True,null=True)
	create_date = models.DateField(auto_now_add=True)
	dod_component = models.CharField(max_length=8)
	dod_it_resource_number = models.CharField(max_length=32)
	system_type = models.CharField(max_length=16)
	point_of_contact = models.ForeignKey(PointOfContact, related_name="systems")

	class Meta:
		db_table = 'system'

	def get_weaknesses(self):
		'''Gets the weaknesses of a specific system'''
		return self.weaknesses.all()

	def get_devices(self):
		'''Gets the devices of a specific system'''
		return self.devices.all()

	def get_system_by_sytem_name(self, system_name):
		'''Get system by system name'''
		return self.objects.filter(name=system_name)


class Weakness(models.Model):
	STATUS_CHOICES = (
		('ao_accepted_risk', 'AO Accepted Risk'),
		('closed', 'Closed'),
		('ongoing', 'Ongoing')
	)

	RAW_SEVERITY_CHOICES = (
		('1', 'I'),
		('2', 'II'),
		('3', 'III')
	)

	MITIGATED_SEVERITY_CHOICES = (
		('null', ''),
		('1', 'I'),
		('2', 'II'),
		('3', 'III')
	)

	title = models.TextField()
	description = models.TextField()
	system = models.ForeignKey(System, related_name="weaknesses")
	point_of_contact = models.ForeignKey(PointOfContact, related_name="weaknesses")
	mitigation = models.TextField()
	resources_required = models.CharField(max_length=16)
	scheduled_completion_date = models.DateField()
	milestone_changes = models.CharField(max_length=16)
	status = models.CharField(max_length=32, choices=STATUS_CHOICES)
	comments = models.TextField()
	raw_severity = models.CharField(max_length=1, choices=RAW_SEVERITY_CHOICES)
	mitigated_severity = models.CharField(max_length=4, choices=MITIGATED_SEVERITY_CHOICES)
	source_identifying_date = models.DateField()
	source_identifying_event = models.CharField(max_length=32)
	source_identifying_tool = models.CharField(max_length=32)
	vuln_id = models.CharField(max_length=16)
	check_contents = models.TextField()
	fix_text = models.TextField()

	class Meta:
		db_table = 'weakness'
		indexes = [
            models.Index(fields=['vuln_id'])
        ]

	def get_weakness_by_vuln_id(self, vuln_id):
		'''Get the weaknesses of a specific vuln'''
		return self.objects.filter(vuln_id=vuln_id)

	def get_weakness_by_scheduled_completion_date(self, date):
		'''Get weaknesses by a scheduled completion date'''
		return self.objects.filter(scheduled_completion_date=date)

	def get_weakness_by_milestone_changes(self, milestone_changes):
		'''Get weaknesses by milestone changes'''
		return self.objects.filter(milestone_changes=milestone_changes)

	def get_weakness_by_status(self, status):
		'''Get weaknesses by status'''
		return self.objects.filter(status=status)

	def get_weakness_by_raw_severity(self, raw_severity):
		'''Get weaknesses by raw severity'''
		return self.objects.filter(raw_severity=raw_severity)

	def get_weakness_by_mitigated_severity(self, mitigated_severity):
		'''Get weaknesses by mitigated severity'''
		return self.objects.filter(mitigated_severity=mitigated_severity)

	def get_weakness_by_raw_severity(self, raw_severity):
		'''Get weaknesses by raw severity'''
		return self.objects.filter(raw_severity=raw_severity)

	def get_weakness_by_source_identifying_date(self, date):
		'''Get weaknesses by source identifying date'''
		return self.objects.filter(source_identifying_date=date)

	def get_weakness_by_source_identifying_tool(self, tool):
		'''Get weaknesses by source identifying tool'''
		return self.objects.filter(source_identifying_tool=tool)

	def get_weakness_by_source_identifying_event(self, event):
		'''Get weaknesses by source identifying event'''
		return self.objects.filter(source_identifying_event=event)

	def get_device(self):
		'''Get weakness devices'''
		return self.devices.device.name

	def get_security_control(self):
		'''Get security control'''
		return self.security_controls.security_control.title


class Device(models.Model):
	name = models.CharField(max_length=32)
	hardware = models.CharField(max_length=32)
	software = models.CharField(max_length=32)
	system = models.ForeignKey(System, related_name="devices")
	ip = models.CharField(max_length=32)

	class Meta:
		db_table = 'device'


class WeaknessSecurityControl(models.Model):
	security_control = models.ForeignKey(SecurityControl, related_name="weaknesses")
	weakness = models.ForeignKey(Weakness, related_name="security_controls")

	class Meta:
		db_table = 'weakness_security_control'
		unique_together = ('security_control', 'weakness')


class DeviceWeakness(models.Model):
	device = models.ForeignKey(Device, related_name="weaknesses")
	weakness = models.ForeignKey(Weakness, related_name="devices")

	class Meta:
		db_table = 'device_weakness'
		unique_together = ('device', 'weakness')

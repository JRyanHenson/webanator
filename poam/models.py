from django.db import models


# Create your models here.
class SecurityControl(models.Model):
    control_number = models.CharField(max_length=32, unique=True)
    description = models.TextField()
    title = models.CharField(max_length=256)

    class Meta:
        db_table = 'security_control'
        unique_together = ('control_number', 'title')


class CCI(models.Model):
    cci = models.CharField(max_length=32, unique=False)
    sc = models.CharField(max_length=32, null=True, blank=True)
    definition = models.TextField(null=True, blank=True)
    scref = models.CharField(max_length=32, null=True, blank=True)

    # class Meta:
    #     db_table = 'cci'
    #     unique_together = ('control_number', 'cci')


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
    name = models.CharField(unique=True, max_length=256)
    update_date = models.DateTimeField(auto_now=True, null=True)
    create_date = models.DateField(auto_now_add=True)
    dod_component = models.CharField(max_length=8)
    dod_it_resource_number = models.CharField(max_length=32)
    system_type = models.CharField(max_length=16)
    point_of_contact = models.ForeignKey(PointOfContact, related_name="systems")

    def __str__(self):
        return self.name

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

    def get_systems(self):
        '''Get all systems'''
        return self.systems.all()


class VulnId(models.Model):
    vuln_id = models.CharField(max_length=16, unique=True)

    class Meta:
        db_table = 'vuln_id'


class CPE(models.Model):
    cpe = models.CharField(max_length=128, unique=True)
    # description = models.TextField()
    # title = models.CharField(max_length=256)

    # class Meta:
    #     db_table = 'cpe'
    #     unique_together = ('device', 'cpe')


class Device(models.Model):
    name = models.CharField(max_length=64)
    os = models.CharField(max_length=256, blank=True, null=True)
    hardware = models.CharField(max_length=64, blank=True, null=True)
    system = models.ForeignKey(System, related_name="devices")
    hostname = models.CharField(max_length=64, blank=True, null=True)
    type = models.CharField(max_length=128, blank=True, null=True)
    ip = models.CharField(max_length=32, blank=True, null=True)
    mac = models.TextField(blank=True, null=True)
    bios_uid = models.CharField(max_length=164, blank=True, null=True)
    netbios_name = models.CharField(max_length=64, blank=True, null=True)
    cpes = models.ManyToManyField(CPE, unique=False, blank=True)


    def __str__(self):
        return self.name

    class Meta:
        db_table = 'device'
        unique_together = ('name', 'system')

    def get_devices(self):
        '''Get all systems'''
        return self.get_devices().all()


class Weakness(models.Model):
    title = models.TextField()
    description = models.TextField(blank=True)
    system = models.ForeignKey(System, related_name="weaknesses")
    point_of_contact = models.ForeignKey(PointOfContact, related_name="weaknesses")
    vuln_id = models.ForeignKey(VulnId, related_name="weaknesses", null=True, blank=True)
    cci = models.ForeignKey(CCI, related_name="weaknesses", null=True, blank=True)
    # cpe = models.ForeignKey(CPE, related_name="weaknesses", null=True, blank=True)
    mitigation = models.TextField(blank=True, null=True)
    security_control = models.TextField(blank=True, null=True)
    resources_required = models.CharField(max_length=16, blank=True, null=True)
    scheduled_completion_date = models.DateField(blank=True, null=True)
    milestone_changes = models.CharField(max_length=16, blank=True, null=True)
    status = models.CharField(max_length=32)
    comments = models.TextField(blank=True, null=True)
    finding_details = models.TextField(blank=True, null=True)
    stig_ref = models.TextField(blank=True, null=True)
    raw_severity = models.CharField(max_length=8, blank=True)
    mitigated_severity = models.CharField(max_length=4, blank=True, null=True)
    source_identifying_date = models.DateField(auto_now=False)
    source_identifying_event = models.CharField(max_length=32)
    source_identifying_tool = models.CharField(max_length=32)
    check_contents = models.TextField(blank=True, null=True)
    fix_text = models.TextField(blank=True, null=True)
    plugin_family = models.TextField(blank=True, null=True)
    plugin_output = models.TextField(blank=True, null=True)
    synopsis = models.TextField(blank=True, null=True)
    credentialed_scan = models.CharField(max_length=16, blank=True, null=True)
    cvss_base_score = models.TextField(blank=True, null=True)
    cvss_temporal_score = models.TextField(blank=True, null=True)
    cvss_vector = models.TextField(blank=True, null=True)
    cvss_temporal_vector = models.TextField(blank=True, null=True)
    cvss3_base_score = models.TextField(blank=True, null=True)
    cvss3_vector = models.TextField(blank=True, null=True)
    exploit_available = models.TextField(blank=True, null=True)
    cve = models.TextField(blank=True, null=True)
    risk_factor = models.TextField(blank=True, null=True)
    vuln_pub_date = models.TextField(blank=True, null=True)
    devices = models.ManyToManyField(Device)

    def __str__(self):
        return self.title

    class Meta:
        db_table = 'weakness'
        indexes = [
            models.Index(fields=['vuln_id'])
        ]

    def get_devices(self):
        '''Get the weakness devices'''
        return self.devices.all()

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


class Document(models.Model):
    description = models.CharField(max_length=255, blank=True)
    document = models.FileField(upload_to='documents/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

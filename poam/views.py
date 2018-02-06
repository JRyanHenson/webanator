from django.shortcuts import render, redirect, reverse
from django.views import generic
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from xml.etree import ElementTree
from django.db import IntegrityError
from django.core.exceptions import ObjectDoesNotExist
from datetime import date
from .forms import *
from .models import *


# Create your views here.
class UploadArtifactView(LoginRequiredMixin, generic.CreateView):
    template_name = 'poam/upload_artifact.html'
    model = Weakness
    form_class = DocumentForm
    def form_valid(self, form):
        data = form.cleaned_data['file']
        source_id = form.cleaned_data['source_identifying_event']
        source_tool = form.cleaned_data['source_identifying_tool']
        source_date = form.cleaned_data['source_identifying_date']
        system = form.cleaned_data['system']
        poc = form.cleaned_data['point_of_contact']
        file_type = form.cleaned_data['file_type']
        # read and parse the file, create a Python dictionary `data_dict` from it
        # start loop here for each Vuln_num in xml upload get Rule_title, Vuln_discuss, Comments, IA_Controls, Check_Content, Severity, Stigid
        # Check and message to make sure Trey or more than likely zac doesn't do something dumb
        if file_type == 'stig_checklist_file':
            tree = ElementTree.parse(data)
            root = tree.getroot()
            if root.tag == "CHECKLIST":
                for vuln in root.findall('.//VULN'):
                    status = vuln.find('STATUS').text
                    comments = vuln.find('COMMENTS').text
                    vuln_id = vuln[0][1].text
                    severity = vuln[1][1].text
                    title = vuln[5][1].text
                    description = vuln[6][1].text
                    ia_control = vuln[7][1].text
                    chk_content = vuln[8][1].text
                    fix_text = vuln[9][1].text
                    try:
                        vuln_id = VulnId(vuln_id=vuln_id)
                        vuln_id.save()
                    except IntegrityError:
                        vuln_id = vuln[0][1].text
                        vuln_id = VulnId.objects.get(vuln_id=vuln_id)
                    if Weakness.objects.filter(system=System.objects.get(name=system), vuln_id=vuln_id).exists():
                        Weakness.objects.filter(system=System.objects.get(name=system), vuln_id=vuln_id).update(comments=comments,
                        raw_severity=severity, source_identifying_event=source_id, source_identifying_tool=source_tool, check_contents=chk_content, fix_text=
                        fix_text, point_of_contact=PointOfContact.objects.get(name=poc), status=status)
                    else:
                        if status == 'Open':
                            weakness_data_dict = {'title': title, 'description': description, 'status': status, 'comments': comments,
                                         'raw_severity': severity, 'source_identifying_event': source_id,
                                         'source_identifying_tool': source_tool, 'vuln_id': vuln_id.id, 'check_contents': chk_content,
                                         'fix_text': fix_text, 'system': System.objects.get(name=system).id,
                                         'point_of_contact': PointOfContact.objects.get(name=poc).id}
                            form = WeaknessModelForm(weakness_data_dict)
                            form.save()
                        else:
                            continue
            else:
                messages.error(self.request, 'Wrong File Type, Zac!')
                return redirect(reverse("poam:upload-artifact"))
        # Check and message to make sure Trey or more than likely Zac doesn't do something dumb
        if file_type == 'nessus_scan_file':
            tree = ElementTree.parse(data)
            root = tree.getroot()
            if root.tag == 'NessusClientData_v2':
                hostname = root.findtext(".//tag[@name='hostname']")
                ip = root.findtext(".//tag[@name='host-ip']")
                os = root.findtext(".//tag[@name='operating-system']")
                credentialed_scan = root.findtext(".//tag[@name='Credentialed_Scan']")
                if hostname is None:
                    hostname = root.findtext(".//tag[@name='netbios-name']")
                if hostname is None:
                    hostname = ip
                try:
                    hostname = Device(name=hostname, system=System.objects.get(name=system))
                    hostname.save()
                except IntegrityError:
                    hostname = root.findtext(".//tag[@name='hostname']")
                    if hostname is None:
                        hostname = root.findtext(".//tag[@name='netbios-name']")
                    if hostname is None:
                        hostname = ip
                    hostname = Device.objects.get(name=hostname)
                if Device.objects.filter(system=System.objects.get(name=system), name=hostname.name).exists():
                    Device.objects.filter(system=System.objects.get(name=system), name=hostname.name).update(os=os, ip=ip)
                else:
                    device_data_dict = {'name' : hostname.name, 'ip' : ip, 'os' : os, 'system': System.objects.get(name=system).id}
                    deviceform = DeviceForm(device_data_dict)
                    deviceform.save()
                for vuln in tree.iter('ReportItem'):
                    vuln_id = vuln.get('pluginID')
                    severity = vuln.get('severity')
                    description = vuln.findtext('description')
                    title = vuln.get('pluginName')
                    plugin_family = vuln.get('pluginFamily')
                    plugin_output = vuln.findtext('plugin_output')
                    fix_text = vuln.findtext('solution')
                    synopsis = vuln.findtext('synopsis')
                    status = 'open'
                    cvss_base_score = vuln.findtext('cvss_base_score')
                    cvss_temporal_score = vuln.findtext('cvss_temporal_score')
                    cvss_vector = vuln.findtext('cvss_vector')
                    cvss_temporal_vector = vuln.findtext('cvss_temporal_vector')
                    exploit_available = vuln.findtext('exploit_available')
                    try:
                        vuln_id = VulnId(vuln_id=vuln_id)
                        vuln_id.save()
                    except IntegrityError:
                        vuln_id = vuln.get('pluginID')
                        vuln_id = VulnId.objects.get(vuln_id=vuln_id)
                    if Weakness.objects.filter(system=System.objects.get(name=system), vuln_id=vuln_id).exists():
                        Weakness.objects.filter(system=System.objects.get(name=system), vuln_id=vuln_id).update(raw_severity=severity,
                            plugin_family=plugin_family, synopsis=synopsis, plugin_output=plugin_output,source_identifying_event=source_id, source_identifying_tool=source_tool,
                            fix_text=fix_text, point_of_contact=PointOfContact.objects.get(name=poc), status=status, cvss_base_score=cvss_base_score,
                            cvss_temporal_score=cvss_temporal_score, cvss_vector=cvss_vector, cvss_temporal_vector=cvss_temporal_vector, exploit_available=exploit_available,
                            credentialed_scan=credentialed_scan)
                    else:
                        if severity != '0':
                            weakness_data_dict = {'title': title, 'description': description, 'status': status,
                                         'raw_severity': severity, 'source_identifying_event': source_id, 'source_identifying_date' : source_date,
                                         'source_identifying_tool': source_tool, 'vuln_id': vuln_id.id,
                                         'fix_text': fix_text, 'system': System.objects.get(name=system).id,
                                         'point_of_contact': PointOfContact.objects.get(name=poc).id,
                                         'plugin_family': plugin_family, 'plugin_output' : plugin_output,
                                         'synopsis' : synopsis, 'credentialed_scan' : credentialed_scan,
                                         'cvss_base_score' : cvss_base_score, 'cvss_temporal_score' : cvss_temporal_score,
                                         'cvss_temporal_vector' : cvss_temporal_vector, 'cvss_vector' : cvss_vector, 'exploit_available' : exploit_available}
                            weaknessform = WeaknessModelForm(weakness_data_dict)
                            weaknessform.save()
                            weakness = Weakness.objects.get(system=System.objects.get(name=system), vuln_id=vuln_id)
                            if DeviceWeakness.objects.filter(device_id=hostname.id, weakness_id=weakness.id).exists():
                                DeviceWeakness.objects.filter(device_id=hostname.id, weakness_id=weakness.id).update(device_id=hostname.id, weakness_id=weakness.id)
                            else:
                                device_weakness_data_dict = {'device': hostname.id, 'weakness': weakness.id}
                                deviceweaknessform = DeviceWeaknessForm(device_weakness_data_dict)
                                deviceweaknessform.save()
                        else:
                            continue


            else:
                messages.error(self.request, 'Wrong File Type, Zac!')
                weaknessform = WeaknessModelForm(weakness_data_dict)
                weaknessform.save()


        # want to close nessus weakness from previous scans on this device
        if Weakness.objects.exclude(system=system, source_identifying_date=source_date).exists():
            messages.success(self.request, 'Credentialed Scan: ' credentialed_scan 'Would you like to close previous ACAS scan results for this device?')
            Weakness.objects.exclude(system=system, source_identifying_date=source_date).update(status='closed')
        # print(weakness)


        messages.success(self.request, 'Artifacts Uploaded Successfully!')
        return redirect(reverse("accounts:dashboard"))


class NewSystemView(LoginRequiredMixin, generic.CreateView):
    template_name= 'poam/new_system.html'
    model = System
    form_class = NewSystemForm

    def form_valid(self, form):
        self.object=form.save()
        return redirect(reverse("poam:upload-artifact"))


class NewPOCView(LoginRequiredMixin, generic.CreateView):
    template_name = 'poam/new_poc.html'
    model = PointOfContact
    form_class = NewPOCForm

    def form_valid(self, form):
        self.object=form.save()
        return redirect(reverse("poam:new-system"))

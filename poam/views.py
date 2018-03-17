from django.shortcuts import render, redirect, reverse
from django.views import generic
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.conf import settings
from xml.etree import ElementTree
from django.db import IntegrityError

import openpyxl
import datetime
import os

from .forms import *
from .models import *


# Create your views here.
class UploadArtifactView(LoginRequiredMixin, generic.CreateView):
    template_name = 'poam/upload_artifact.html'
    model = Weakness
    form_class = DocumentForm

    def get(self, request, *args, **kwargs):
        system = System.objects.get(id=self.kwargs['pk'])
        form = self.form_class(initial=self.initial, system=system)
        return render(request, self.template_name, {'form': form, 'system': system})

    def get_form_kwargs(self):
        kwargs = super(UploadArtifactView, self).get_form_kwargs()
        kwargs['system'] = System.objects.get(id=self.kwargs['pk'])
        return kwargs

    def form_valid(self, form):
        data = form.cleaned_data['file']
        source_id = form.cleaned_data['source_identifying_event']
        source_tool = form.cleaned_data['source_identifying_tool']
        source_date = form.cleaned_data['source_identifying_date']
        system = System.objects.get(id=self.kwargs['pk'])
        poc = form.cleaned_data['point_of_contact']
        file_type = form.cleaned_data['file_type']
        device = form.cleaned_data['devices']

        # read and parse the file, create a Python dictionary `data_dict` from it
        # start loop here for each Vuln_num in xml upload get Rule_title, Vuln_discuss,
        # Comments, IA_Controls, Check_Content, Severity, Stigid
        # Need check and message to make sure Trey or more than likely Zac doesn't do something dumb
        if file_type == 'stig_checklist_file':
            tree = ElementTree.parse(data)
            root = tree.getroot()
            if root.tag == "CHECKLIST":
                for vuln in root.findall('.//VULN'):
                    status = vuln.find('STATUS').text
                    comments = vuln.find('COMMENTS').text
                    severity = vuln[1][1].text
                    title = vuln[5][1].text
                    description = vuln[6][1].text
                    chk_content = vuln[8][1].text
                    fix_text = vuln[9][1].text
                    try:
                        vuln_id = VulnId(vuln_id=vuln[0][1].text)
                        vuln_id.save()
                    except IntegrityError:
                        vuln_id = VulnId.objects.get(vuln_id=vuln[0][1].text)
                    if Weakness.objects.filter(system=system, vuln_id=vuln_id).exists():
                        Weakness.objects.filter(system=system, vuln_id=vuln_id).update(comments=comments,
                        raw_severity=severity, source_identifying_event=source_id,
                        source_identifying_tool=source_tool, check_contents=chk_content, fix_text=fix_text,
                        point_of_contact=PointOfContact.objects.get(name=poc), status=status)
                    else:
                        if status == 'Open':
                            # weakness = Weakness.objects.create(title=title, description=description, status=status, comments=comments, raw_severity=severity, source_identifying_event=source_id, source_identifying_tool=source_tool, source_identifying_date=source_date, vuln_id=vuln_id, check_contents=chk_content, fix_text=fix_text, system=system, point_of_contact=PointOfContact.objects.get(name=poc))
                            data_dict = {'title': title, 'description': description, 'status': status,
                                         'comments': comments, 'raw_severity': severity, 'source_identifying_event': source_id,
                                         'source_identifying_tool': source_tool, 'source_identifying_date' : source_date, 'vuln_id': vuln_id.id,
                                         'check_contents': chk_content, 'fix_text': fix_text, 'system': system.id,
                                         'point_of_contact': PointOfContact.objects.get(name=poc).id, 'devices': device}
                            if vuln[7][1].text is not None:
                                try:
                                    ia_control = SecurityControl(control_number=vuln[7][1].text, title='',
                                                                 description='')
                                    ia_control.save()
                                    ia_control = SecurityControl.objects.filter(id=ia_control.id)
                                except IntegrityError:
                                    ia_control = SecurityControl.objects.filter(control_number=vuln[7][1].text)
                                data_dict['security_control'] = ia_control
                            form = WeaknessModelForm(data_dict)
                            try:
                                form.save()
                            except:
                                messages.error(self.request, '{} had error when saving to database. {}'.format(vuln_id.vuln_id, form.errors))
                        else:
                            continue
            else:
                messages.error(self.request, 'Wrong File Type, Zac!')
                return redirect(reverse("poam:upload-artifact"))
        elif file_type == 'rmf_control_review_file':
            try:
                wb = openpyxl.load_workbook(data)
                sheet = wb.active
            except:
                messages.error(self.request, 'Wrong File Type, Zac!')
                return redirect(reverse("poam:upload-artifact"))
            else:
                for row in range(2, sheet.max_row + 1):
                    title = sheet['C{}'.format(row)].value
                    status = sheet['D{}'.format(row)].value
                    comments = sheet['E{}'.format(row)].value
                    control_number = sheet['B{}'.format(row)].value
                    try:
                        security_control = SecurityControl(title=title, control_number=control_number, description='')
                        security_control.save()
                        security_controls = SecurityControl.objects.filter(control_number=control_number)
                    except IntegrityError:
                        security_control = SecurityControl.objects.get(control_number=control_number)
                        security_controls = SecurityControl.objects.filter(control_number=control_number)

                    if Weakness.objects.filter(title=title, security_control__id=security_control.id).exists():
                        Weakness.objects.filter(title=title, security_control=security_controls).update(status=status, comments=comments, source_identifying_event=source_id, source_identifying_tool=source_tool, devices=device, security_control=security_controls, source_identifying_date=source_date, system=System.objects.get(name=system).id, point_of_contact=PointOfContact.objects.get(name=poc).id)
                    else:
                        if status == 'Planned':
                            data_dict = {'title': title, 'description': '', 'status': status, 'comments': comments, 'source_identifying_event': source_id, 'source_identifying_tool': source_tool, 'devices': device, 'security_control': security_controls, 'source_identifying_date' : source_date, 'system': System.objects.get(name=system).id, 'point_of_contact': PointOfContact.objects.get(name=poc).id}
                            form = WeaknessModelForm(data_dict)
                            try:
                                form.save()
                            except:
                                messages.error(self.request, form.errors)
        elif file_type == 'nessus_scan_file':
            # parse data from nessus file and define as tree then get the root of the xml file
            tree = ElementTree.parse(data)
            root = tree.getroot()
            # verify that the file is in fact a nessus file by checking the root tag of the xml
            if root.tag == 'NessusClientData_v2':
                # define static variables from nessus file
                # hostname = root.findtext(".//tag[@name='hostname']")
                ip = root.findtext(".//tag[@name='host-ip']")
                os = root.findtext(".//tag[@name='operating-system']")
                credentialed_scan = root.findtext(".//tag[@name='Credentialed_Scan']")
                # not all nessus files have an input for hostname statements below corrects possible exception by using netbios name or ip
                # if hostname is None:
                #     hostname = root.findtext(".//tag[@name='netbios-name']")
                # if hostname is None:
                #     hostname = ip
                # check to see if device object exists. if so, updates os and ip in existing device object
                for specific_device in device:
                    if Device.objects.filter(system=system, name=specific_device).exists():
                        Device.objects.filter(system=system, name=specific_device).update(os=os, ip=ip)
                        specific_device = Device.objects.get(name=specific_device)
                    # if device doesn't exists, creates new object using data dictionary file
                    else:
                        # throw error - work on for later
                        device_data_dict = {'name' : specific_device, 'ip' : ip, 'os' : os, 'system': system.id}
                        deviceform = DeviceForm(device_data_dict)
                        deviceform.save()
                        specific_device = Device.objects.get(name=specific_device)
                    # for loop of nessus xml file to get relevant weakness information
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
                        # try block to test to see if vuln_id already exists in DB. if not, creates object
                        try:
                            vuln_id = VulnId(vuln_id=vuln_id)
                            vuln_id.save()
                        except IntegrityError:
                            vuln_id = vuln.get('pluginID')
                            vuln_id = VulnId.objects.get(vuln_id=vuln_id)
                        # checks to see if weakness object with this hostname and vuln id already exists. if so, it updates existing object
                        if Weakness.objects.filter(devices__id=specific_device.id, vuln_id=vuln_id).exists():
                            Weakness.objects.filter(devices__id=specific_device.id, vuln_id=vuln_id).update(raw_severity=severity,
                                plugin_family=plugin_family, synopsis=synopsis, plugin_output=plugin_output,source_identifying_event=source_id, source_identifying_tool=source_tool,
                                fix_text=fix_text, point_of_contact=PointOfContact.objects.get(name=poc), status=status, cvss_base_score=cvss_base_score,
                                cvss_temporal_score=cvss_temporal_score, cvss_vector=cvss_vector, cvss_temporal_vector=cvss_temporal_vector, exploit_available=exploit_available,
                                credentialed_scan=credentialed_scan)
                        else:
                            # if severity is not 0 then create and new weakness object using a data dictionary file
                            if severity != '0':
                                weakness_data_dict = {'title': title, 'system': system.id, 'description': description, 'status': status,
                                             'raw_severity': severity, 'source_identifying_event': source_id, 'source_identifying_date' : source_date,
                                             'source_identifying_tool': source_tool, 'vuln_id': vuln_id.id,
                                             'fix_text': fix_text, 'devices': device,
                                             'point_of_contact': PointOfContact.objects.get(name=poc).id,
                                             'plugin_family': plugin_family, 'plugin_output' : plugin_output,
                                             'synopsis' : synopsis, 'credentialed_scan' : credentialed_scan,
                                             'cvss_base_score' : cvss_base_score, 'cvss_temporal_score' : cvss_temporal_score,
                                             'cvss_temporal_vector' : cvss_temporal_vector, 'cvss_vector' : cvss_vector, 'exploit_available' : exploit_available}
                                weaknessform = WeaknessModelForm(weakness_data_dict)
                                weaknessform.save()
                                # checks for weakness objects created before the date of the current upload. if date is different,
                                # updates weakness object to mark previous results as closed. eventually add logic to get user confirmation
                                if Weakness.objects.exclude(devices__id=specific_device.id, source_identifying_date=source_date).exists():
                                    messages.success(self.request, 'Credentialed Scan: ' + credentialed_scan + ' Previous scan results will be closed')
                                    Weakness.objects.exclude(devices__id=specific_device.id, source_identifying_date=source_date).update(status='closed')
                            else:
                                continue
            else:
                messages.error(self.request, 'Wrong File Type, Zac!')
                weaknessform = WeaknessModelForm()
                weaknessform.save()
        # want to close nessus weakness from previous scans on this device
        if Weakness.objects.exclude(system=system, source_identifying_date=source_date).exists():
            messages.success(self.request, 'Credentialed Scan: {} Would you like to close previous ACAS scan results for this device?'.format(credentialed_scan))
            Weakness.objects.exclude(system=system, source_identifying_date=source_date).update(status='closed')

        messages.success(self.request, 'Artifacts Uploaded Successfully!')
        return redirect(reverse('poam:edit-system', kwargs={'pk': self.kwargs['pk']}))


class NewSystemView(LoginRequiredMixin, generic.CreateView):
    template_name= 'poam/new_system.html'
    model = System
    form_class = NewSystemForm

    def form_valid(self, form):
        self.object=form.save()
        return redirect(reverse('accounts:dashboard'))


class NewPOCView(LoginRequiredMixin, generic.CreateView):
    template_name = 'poam/new_poc.html'
    model = PointOfContact
    form_class = NewPOCForm

    def form_valid(self, form):
        self.object=form.save()
        return redirect(reverse("poam:new-system"))


class SelectSystemView(LoginRequiredMixin, generic.ListView):
    template_name = "poam/select-system.html"
    model = System
    context_object_name = 'systems'

    def post(self, request, *args, **kwargs):
        form = request.POST
        system = form['system']
        return redirect(reverse('poam:edit-system', kwargs={'pk': system}))


class EditSystemView(LoginRequiredMixin, generic.DetailView):
    template_name = "poam/edit-system.html"
    model = System


class AddDeviceView(LoginRequiredMixin, generic.CreateView):
    template_name = "poam/add-device.html"
    model = Device
    form_class = AddDeviceForm

    def get_context_data(self, **kwargs):
        context = super(AddDeviceView, self).get_context_data(**kwargs)
        context['system'] = System.objects.get(id=self.kwargs['pk'])
        return context

    def form_valid(self, form):
        device = form.save(commit=False)
        device.system = System.objects.get(id=self.kwargs['pk'])
        device.save()
        messages.success(self.request, 'Device Added Successfully!')
        return redirect(reverse('poam:edit-system', kwargs={'pk': self.kwargs['pk']}))


class ExportSystemView(LoginRequiredMixin, generic.DetailView):
    template_name = 'poam/edit-system.html'
    model = System

    def get(self, request, *args, **kwargs):
        fp = openpyxl.load_workbook('{}/template.xlsx'.format(settings.MEDIA_ROOT))
        ws = fp['POAM']

        ws['B1'] = self.get_object().create_date
        ws['B2'] = self.get_object().update_date
        ws['B3'] = self.get_object().dod_component
        ws['B4'] = self.get_object().name
        ws['B5'] = self.get_object().dod_it_resource_number

        ws['H1'] = self.get_object().system_type
        ws['H3'] = self.get_object().point_of_contact.name
        ws['H4'] = self.get_object().point_of_contact.phone
        ws['H5'] = self.get_object().point_of_contact.email

        poams = self.get_object().get_weaknesses()
        row = 7
        for poam in poams:
            weakness = ''
            if poam.vuln_id:
                weakness += '{}\n'.format(poam.vuln_id.vuln_id)
            weakness += 'Title:{}\n'.format(poam.title)
            weakness += '\nDescription:{}'.format(poam.description)
            weakness += '\n\nDevices Affected:\n'
            for device in poam.devices.all():
                weakness += '{}\n'.format(device.name)
            ws['A{}'.format(row)] = weakness
            ws['B{}'.format(row)] = poam.raw_severity
            sc = ''
            security_controls = poam.security_control.all()
            for security_control in security_controls:
                sc += '{}'.format(security_control.control_number)
            ws['C{}'.format(row)] = sc
            ws['D{}'.format(row)] = poam.mitigated_severity
            ws['E{}'.format(row)] = poam.mitigation

            poc = ''
            poc += '{}\n'.format(poam.point_of_contact.name)
            poc += '{}\n'.format(poam.point_of_contact.email)
            poc += '{}\n'.format(poam.point_of_contact.phone)

            ws['F{}'.format(row)] = poc
            ws['G{}'.format(row)] = poam.resources_required
            ws['H{}'.format(row)] = poam.scheduled_completion_date
            ws['I{}'.format(row)] = poam.milestone_changes

            source_identifying_weakness = ''
            source_identifying_weakness += '1. {}\n'.format(poam.source_identifying_event)
            source_identifying_weakness += '2. {}\n'.format(poam.source_identifying_tool)
            source_identifying_weakness += '3. {}\n'.format(poam.source_identifying_date)

            ws['J{}'.format(row)] = source_identifying_weakness
            ws['K{}'.format(row)] = poam.status
            ws['L{}'.format(row)] = poam.comments
            row += 1

        filename = '{}_{}.xlsx'.format(datetime.date.today(), self.get_object().name)
        fp.save('{}/poam/{}'.format(settings.MEDIA_ROOT, filename))

        fp = openpyxl.load_workbook('{}/poam/{}'.format(settings.MEDIA_ROOT, filename))
        httpresponse = HttpResponse(openpyxl.writer.excel.save_virtual_workbook(fp), content_type='application/vnd.ms-excel')
        httpresponse['Content-Disposition'] = 'attachment; filename={}'.format(filename)
        return httpresponse

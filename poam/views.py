from django.shortcuts import render, redirect, reverse
from django.views import generic
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from xml.etree import ElementTree
from django.db import IntegrityError

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
        system = form.cleaned_data['system']
        poc = form.cleaned_data['point_of_contact']
        file_type = form.cleaned_data['file_type']

        # read and parse the file, create a Python dictionary `data_dict` from it
        # start loop here for each Vuln_num in xml upload get Rule_title, Vuln_discuss, Comments, IA_Controls, Check_Content, Severity, Stigid
        if file_type == 'stig_checklist_file':
            # Need check and message to make sure Trey or more than likely zac doesn't do something dumb
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
                    print(vuln_id.vuln_id)
                    if Weakness.objects.filter(system=System.objects.get(name=system), vuln_id=vuln_id).exists():
                        Weakness.objects.filter(system=System.objects.get(name=system), vuln_id=vuln_id).update(comments=comments,
                        raw_severity=severity, source_identifying_event=source_id, source_identifying_tool=source_tool, check_contents=chk_content, fix_text=
                        fix_text, point_of_contact=PointOfContact.objects.get(name=poc), status=status)
                    else:
                        if status == 'Open':
                            data_dict = {'title': title, 'description': description, 'status': status, 'comments': comments,
                                         'raw_severity': severity, 'source_identifying_event': source_id,
                                         'source_identifying_tool': source_tool, 'vuln_id': vuln_id.id, 'check_contents': chk_content,
                                         'fix_text': fix_text, 'system': System.objects.get(name=system).id,
                                         'point_of_contact': PointOfContact.objects.get(name=poc).id}
                            form = DocumentModelForm(data_dict)
                            form.save()
                        else:
                            continue
            else:
                messages.error(self.request, 'Wrong File Type, Zac!')
                return redirect(reverse("poam:upload-artifact"))

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

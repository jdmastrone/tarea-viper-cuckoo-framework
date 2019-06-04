# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

# Standard Imports
import os
import re
import json
import tempfile
import contextlib
import shutil
import requests
import platform
import requests
import unicodedata
import time

from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
from datetime import datetime
from operator import itemgetter

# Logging
import logging

# Django Imports
from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import HttpResponse, Http404
# from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.contrib import messages
from django.core.files.temp import NamedTemporaryFile

# Viper imports
from viper.common import network
from viper.common.autorun import autorun_module
from viper.common.objects import File
from viper.common.version import __version__
from viper.core.archiver import Extractor
from viper.core.config import __config__
from viper.core.database import Database
from viper.core.plugins import __modules__
from viper.core.project import __project__, get_project_list
from viper.core.session import __sessions__
from viper.core.storage import store_sample, get_sample_path
from viper.core.ui.commands import Commands

try:
    from scandir import walk  # noqa
except ImportError:
    from os import walk  # noqa
try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput  # commands was deprecated in Py2.

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError  # Py2

log = logging.getLogger("viper-web")
cfg = __config__


##
# Helper Functions
##

# Module Dicts (see also viper_dropdown.js) - TODO(frennkie) can this be auto generated (introspection)?!
mod_dict = {'apk': {'help': '-h',
                    'info': '-i',
                    'perm': '-p',
                    'list': '-f',
                    'all': '-a',
                    'dump': '-d'},
            'clamav': {'run': ''},
            'debup': {'info': '',
                      'extract': '-s'},
            'editdistance': {'run': ''},
            'elf': {'sections': '--sections',
                    'segments': '--segments',
                    'symbols': '--symbols',
                    'interp': '--interpreter',
                    'dynamic': '--dynamic'},
            'email': {'envelope': '-e',
                      'attach': '-f',
                      'header': '-r',
                      'trace': '-t',
                      'traceall': '-T',
                      'spoof': '-s',
                      'all': '-a'},
            'exif': {'run': ''},
            'fuzzy': {'run': ''},
            'html': {'scripts': '-s',
                     'links': '-l',
                     'iframe': '-f',
                     'embed': '-e',
                     'images': '-i',
                     'dump': '-d'},
            'idx': {'run': ''},
            'image': {'ghiro': '--ghiro'},
            'jar': {'run': ''},
            'office': {'meta': '-m',
                       'oleid': '-o',
                       'streams': '-s',
                       'export': '-e'},
            'pdf': {'id': 'id',
                    'streams': 'streams'},
            'pe': {'imports': 'imports',
                   'exports': 'exports',
                   'res': 'resources',
                   'imp': 'imphash',
                   'compile': 'compiletime',
                   'peid': 'peid',
                   'security': 'security',
                   'language': 'language',
                   'sections': 'sections',
                   'pehash': 'pehash'},
            'rat': {'auto': '-a', 'list': '-l'},
            'reports': {'malwr': '--malwr',
                        'anubis': '--anubis',
                        'threat': '--threat',
                        'joe': '--joe',
                        'meta': '--meta'},
            'shellcode': {'run': ''},
            'strings': {'all': '-a',
                        'hosts': '-H'},
            'swf': {'decom': 'decompress'},
            'virustotal': {'scan': '',
                           'submit': '-s'},
            'xor': {'xor': '',
                    'rot': '-r',
                    'all': '-a',
                    'export': '-o'},
            'yara': {'scan': 'scan -t',
                     'all': 'scan -a -t',
                     'rules': 'rules'}
            }


# context manager for file uploader
@contextlib.contextmanager
def upload_temp():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


def open_db(project):
    # Check for valid project
    if project == 'default':
        __project__.open(project)
        return Database()
    else:
        try:
            __project__.open(project)
            return Database()
        except Exception:
            return False


def print_output(output):
    if not output:
        return '<p class="text-danger">! The command Generated no Output</p>'
    return_html = ''
    for entry in output:
        # Skip lines that say seesion opened
        if 'Session opened on' in entry['data']:
            continue
        if entry['type'] == 'info':
            return_html += '<p class="text-primary">{0}</p>'.format(entry['data'])
            # self.log('info', entry['data'])
        elif entry['type'] == 'item':
            return_html += '<li class="text-primary">{0}</li>'.format(entry['data'])
        elif entry['type'] == 'warning':
            return_html += '<p class="text-warning">{0}</p>'.format(entry['data'])
        elif entry['type'] == 'error':
            return_html += '<p class="text-danger">{0}</p>'.format(entry['data'])
        elif entry['type'] == 'success':
            return_html += '<p class="text-success">{0}</p>'.format(entry['data'])
        elif entry['type'] == 'table':
            # set the table
            return_html += '<table class="table table-bordered">'
            # Column Titles
            return_html += '<tr>'
            for column in entry['data']['header']:
                return_html += '<th>{0}</th>'.format(column)
            return_html += '</tr>'
            # Rows
            for row in entry['data']['rows']:
                return_html += '<tr>'
                for cell in row:
                    return_html += '<td>{0}</td>'.format(cell)
                return_html += '</tr>'
            # Close table
            return_html += '</table>'
        else:
            return_html += '<p>{0}</p>'.format(entry['data'])
    return return_html


def parse(data):
    args = []
    # Split words by white space.
    words = data.split()
    # First word is the root command.
    root = words[0]
    # If there are more words, populate the arguments list.
    if len(words) > 1:
        args = words[1:]
    return root, args


def parse_text(module_text):
    # String to hold the new text
    set_text = ''
    # Split in to lines.
    for line in module_text.split('\n'):
        # Remove the colour codes
        line = re.sub(r'\[(\d)+m', '', line.replace(r'\x1b', ''))
        # Ignore the line that says we opened a session
        if 'Session opened on' in line:
            continue
        # add text the string
        set_text += '{0}\n'.format(line)
    return set_text


# this will allow complex command line parameters to be passed in via the web gui
def module_cmdline(project=None, cmd_line=None, file_hash=None):
    html = ""
    cmd = Commands()
    split_commands = cmd_line.split(';')
    for split_command in split_commands:
        split_command = split_command.strip()
        if not split_command:
            continue
        root, args = parse(split_command)
        try:
            if root in cmd.commands:
                cmd_to_run = cmd.commands[root]['obj']
                cmd_to_run(*args)
                cmd_instance = cmd_to_run.__self__
                html += print_output(cmd_instance.output)
                del (cmd_instance.output[:])
            elif root in __modules__:
                # if prev commands did not open a session open one on the current file
                if file_hash:
                    __project__.open(project)
                    path = get_sample_path(file_hash)
                    __sessions__.new(path)
                module = __modules__[root]['obj']()
                module.set_commandline(args)
                module.run()

                html += print_output(module.output)
                if cfg.modules.store_output and __sessions__.is_set():
                    Database().add_analysis(file_hash, split_command, module.output)
                del (module.output[:])
            else:
                html += '<p class="text-danger">{0} is not a valid command</p>'.format(cmd_line)
        except Exception:
            html += '<p class="text-danger">We were unable to complete the command {0}</p>'.format(cmd_line)
    __sessions__.close()
    return html


def add_file(file_path, name=None, tags=None, parent=None):
    obj = File(file_path)
    print('prueba_nombre: ' + obj.name)
    new_path = store_sample(obj)
    print(new_path)

    if not name:
        name = os.path.basename(file_path)

    # success = True
    if new_path:
        # Add file to the database.
        db = Database()
        db.add(obj=obj, name=name, tags=tags, parent_sha=parent)

        # AutoRun Modules
        if cfg.autorun.enabled:
            autorun_module(obj.sha256)
            # Close the open session to keep the session table clean
            __sessions__.close()
        return obj.sha256

    else:
        # ToDo Remove the stored file if we cant write to DB
        return


##
# Class Based Views
##

# Main Page
class MainPageView(LoginRequiredMixin, TemplateView):
    """Main Page"""
    def get(self, request, *args, **kwargs):
        template_name = "viperweb/index.html"

        # default to "default" project if none given
        project = kwargs.get('project', 'default')
        db = open_db(project)

        # Get all Samples
        sample_list = db.find('all')

        return render(request, template_name, {'sample_list': sample_list,
                                               'extractors': Extractor().extractors,
                                               'project': project,
                                               'projects': get_project_list()})


class UrlDownloadView(LoginRequiredMixin, TemplateView):
    """Download a file from URL and add to project"""
    def get(self, request, *args, **kwargs):
        return HttpResponse('This is a POST only view')

    def post(self, request, *args, **kwargs):
        # Set Project
        project = request.POST.get('project', 'default')
        open_db(project)

        url = request.POST.get('url')
        tags = request.POST.get('tag_list')
        tags = "url," + tags

        if request.POST.get('tor'):
            downloaded_file = network.download(url, tor=True)
        else:
            downloaded_file = network.download(url, tor=False)

        if downloaded_file is None:
            messages.error(request, "server can't download from URL")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        tf = NamedTemporaryFile()
        tf.write(downloaded_file)

        if not tf:
            messages.error(request, "server can't download from URL")
            return redirect(reverse("main-page-project", kwargs={"project": project}))
        tf.flush()

        sha_256 = add_file(tf.name, name=url.split('/')[-1], tags=tags)
        if sha_256:
            messages.success(request, "stored file in database: {}".format(tf.name))
            return redirect(reverse('main-page-project', kwargs={'project': project}))
        else:
            messages.error(request, "Unable to Store The File, already in database")
            return redirect(reverse("main-page-project", kwargs={"project": project}))


class VtDownloadView(LoginRequiredMixin, TemplateView):
    """Download a file from Virustotal and add to project"""
    def get(self, request, *args, **kwargs):
        return HttpResponse('This is a POST only view')

    # VirusTotal Download
    # TODO(frennkie) this most likely doesn't work
    #   virustotal -d does not take a parameter - so providing a vt_hash will fail
    #   virustotal --search <vt_hash> -d would make sense but requires a API key for the
    #   private VT API (which I don't have)

    def post(self, request, *args, **kwargs):
        # Set Project
        project = request.POST.get('project', 'default')
        open_db(project)

        vt_hash = request.POST.get('vt_hash')
        tags = request.POST.get('tag_list')
        cmd_line = 'virustotal --search {0} -d; store'.format(vt_hash)
        if len(tags) > 0:
          cmd_line += '; tags -a {0}'.format(tags)

        module_results = module_cmdline(project=project, file_hash=False, cmd_line=cmd_line)

        if 'Stored' in module_results:
            return redirect(reverse("main-page-project", kwargs={"project": project}))
        else:
            messages.error(request, "Unable to download file {0}".format(module_results))
            return redirect(reverse("main-page-project", kwargs={"project": project}))


# File View
class FileView(LoginRequiredMixin, TemplateView):
    """Show details for a file/sample"""
    def get(self, request, *args, **kwargs):
        template_name = "viperweb/file.html"

        # default to "default" project if none given
        project = kwargs.get('project', 'default')
        db = open_db(project)

        sha256 = kwargs.get('sha256')
        if not sha256:
            log.error("no sha256 hashed provided")
            raise Http404("no sha256 hashed provided")

        path = get_sample_path(sha256)
        if not path:
            raise Http404("could not retrieve file for sha256 hash: {}".format(sha256))

        # Get additional details for file
        malware = db.find(key='sha256', value=sha256)
        try:
            malware_obj = malware[0]
        except IndexError:
            raise Http404("could not find file for sha256 hash: {}".format(sha256))

        note_list = []
        notes = malware_obj.note
        if notes:
            for note in notes:
                note_list.append({'title': note.title,
                                  'body': note.body,
                                  'id': note.id})

        tag_list = None
        children = None
        parent = None
        apis_list = []
        fcr_list = []
        rw_list = []
        dl_list = []
        fo_list = []
        fco_list = []
        ro_list = []
        cl_list = []
        fw_list = []
        fd_list = []
        mx_list = []
        fr_list = []
        rr_list = []
        de_list = []

        if not malware_obj.type[:4] == 'PE32':
            filedata = open(path, 'rb').read()
            if malware_obj.type_olevba is None:
                vbaparser = VBA_Parser(path, data=filedata)
                if not vbaparser.type is None:
                    db.update_malware_olevba(malware_obj.id,str(vbaparser.type))
                if vbaparser.detect_vba_macros():
                    for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                        db.add_malwaremacros(sha256,str(filename),str(stream_path),str(vba_filename),str(vba_code))
                    for (type, keyword, description) in vbaparser.analyze_macros():
                        db.add_malwareanalysismacros(sha256,str(type),str(keyword),str(description))
        else:
            tag_list = db.list_tags_for_malware(sha256)
            children = db.list_children(malware_obj.id)
            parent = db.get_parent(malware_obj.id)
            ruta = '{0}/tasks/report/{1}'.format(cfg.cuckoo.cuckoo_host, str(malware_obj.task_id))
            resp = requests.get(ruta)
            if resp.status_code == 200:
                jdata = resp.json()
                if 'behavior' in jdata:
                    for apis in jdata['behavior']['apistats']:
                        for api in jdata['behavior']['apistats'][apis]:
                            apis_list.append({'api': api})
                    for fcr in jdata['behavior']['summary']['file_created']:
                        fcr_list.append({'fcr': fcr})
                    for rw in jdata['behavior']['summary']['regkey_written']:
                        rw_list.append({'rw': rw})
                    for dl in jdata['behavior']['summary']['dll_loaded']:
                        dl_list.append({'dl': dl})
                    for fo in jdata['behavior']['summary']['file_opened']:
                        fo_list.append({'fo': fo})
                    for fco in jdata['behavior']['summary']['file_copied']:
                        fco_list.append({'fco': fco})
                    for ro in jdata['behavior']['summary']['regkey_opened']:
                        ro_list.append({'ro': ro})
                    for cl in jdata['behavior']['summary']['command_line']:
                        cl_list.append({'cl': cl})
                    for fw in jdata['behavior']['summary']['file_written']:
                        fw_list.append({'fw': fw})
                    for fd in jdata['behavior']['summary']['file_deleted']:
                        fd_list.append({'fd': fd})
                    for mx in jdata['behavior']['summary']['mutex']:
                        mx_list.append({'mx': mx})
                    for fr in jdata['behavior']['summary']['file_read']:
                        fr_list.append({'fr': fr})
                    for rr in jdata['behavior']['summary']['regkey_read']:
                        rr_list.append({'rr': rr})
                    for de in jdata['behavior']['summary']['directory_enumerated']:
                        de_list.append({'de': de})

        try:
            malwarevt = db.get_malwarevt(malware_obj.malwarevt[0].id)
            update_vt_value(path,project,sha256)
        except:
            malwarevt = None
            print('No cuenta con información de Virus Total')
            get_vt_value(path,project,sha256)
            malware = db.find(key='sha256', value=sha256)
            malware_obj = malware[0]
            try:
                malwarevt = db.get_malwarevt(malware_obj.malwarevt[0].id)
            except:
                malwarevt = None

        malwarevtsc_list = []
        malwarevtsc = malware_obj.malwarevtsc
        if malwarevtsc:
            for scan in malwarevtsc:
                malwarevtsc_list.append({'antivirus': scan.antivirus,
                                         'detected': scan.detected,
                                         'version': scan.version,
                                         'result': scan.result,
                                         'update': scan.update})

        malwaremacros_list = []
        malwaremacros = malware_obj.malwaremacros
        if malwaremacros:
            for macros in malwaremacros:
                malwaremacros_list.append({'filename': macros.filename,
                                         'streampath': macros.streampath,
                                         'vbafilename': macros.vbafilename,
                                         'vbacode': macros.vbacode})
        malwareanalysismacros_list = []
        malwareanalysismacros = malware_obj.malwareanalysismacros
        if malwareanalysismacros:
            for analysismacros in malwareanalysismacros:
                malwareanalysismacros_list.append({'type': analysismacros.type,
                                         'keyword': analysismacros.keyword,
                                         'description': analysismacros.description})
        module_history = []
        analysis_list = malware_obj.analysis
        if analysis_list:
            for item in analysis_list:
                module_history.append({'id': item.id,
                                       'cmd_line': item.cmd_line})

        return render(request, template_name, {'malware': malware_obj,
                                               'malwaremacros_list': malwaremacros_list,
                                               'malwareanalysismacros_list': malwareanalysismacros_list,
                                               'fcr_list': fcr_list,
                                               'rw_list': rw_list,
                                               'dl_list': dl_list,
                                               'fo_list': fo_list,
                                               'fco_list': fco_list,
                                               'ro_list': ro_list,
                                               'cl_list': cl_list,
                                               'fw_list': fw_list,
                                               'fd_list': fd_list,
                                               'mx_list': mx_list,
                                               'fr_list': fr_list,
                                               'rr_list': rr_list,
                                               'de_list': de_list,
                                               'apis_list': apis_list,
					                           'malwarevt': malwarevt,
                                               'note_list': note_list,
                                               'malwarevtsc_list': malwarevtsc_list,
                                               'tag_list': tag_list,
                                               'children': children,
                                               'parent': parent,
                                               'module_history': module_history,
                                               'project': project,
                                               'projects': get_project_list()})

class RunModuleView(LoginRequiredMixin, TemplateView):
    """Run a module and return output"""
    def get(self, request, *args, **kwargs):
        return HttpResponse('This is a POST only view')

    def post(self, request, *args, **kwargs):
        # Get the project and hash of the file we want to run a command against
        project = kwargs.get('project', 'default')
        file_hash = request.POST.get('file_hash')

        if len(file_hash) != 64:
            file_hash = False
        # Lot of logic here to decide what command you entered.
        module_name = request.POST.get('module')
        print("Here: {}".format(module_name))
        if module_name == "module":
            return HttpResponse("<pre>Error: No Module selected!</pre>")
        module_args = request.POST.get('args')
        cmd_line = request.POST.get('cmdline')
        module_history = request.POST.get('moduleHistory', ' ')
        cmd_string = ''
        # Order of precedence
        # moduleHistory, cmd_line, module_name

        if module_history != ' ':
            result = Database().get_analysis(module_history)
            module_results = print_output(json.loads(result.results))
            html = '<p class="text-success">Result for "{0}" stored on {1}</p>'.format(result.cmd_line, result.stored_at)
            html += str(parse_text(module_results))
            return HttpResponse('<pre>{0}</pre>'.format(html))
        if cmd_line:
            cmd_string = cmd_line
        elif module_args:
            cmd_string = '{0} {1}'.format(module_name, mod_dict[module_name][module_args])
        module_results = module_cmdline(project=project, file_hash=file_hash, cmd_line=cmd_string)
        return HttpResponse('<pre>{0}</pre>'.format(str(parse_text(module_results))))


class HexView(LoginRequiredMixin, TemplateView):
    """Read file a return as Hex"""
    def get(self, request, *args, **kwargs):
        return HttpResponse('This is a POST only view')

    def post(self, request, *args, **kwargs):
        # Get the project and hash of the file
        project = kwargs.get('project', 'default')
        file_hash = request.POST.get('file_hash')
        try:
            hex_offset = int(request.POST.get('hex_start'))
        except Exception:
            return '<p class="text-danger">Error Generating Request</p>'
        hex_length = 256

        # get file path
        __project__.open(project)
        hex_path = get_sample_path(file_hash)

        # create the command string
        hex_cmd = 'hd -s {0} -n {1} {2}'.format(hex_offset, hex_length, hex_path)
        if platform.system() == 'Darwin':
            hex_cmd = 'xxd -s {0} -l {1} {2}'.format(hex_offset, hex_length, hex_path)

        # get the output
        hex_string = getoutput(hex_cmd)
        # Format the data
        html_string = ''
        hex_rows = hex_string.split('\n')
        for row in hex_rows:
            if len(row) > 9:
                off_str = row[0:8]
                hex_str = row[9:58]
                asc_str = row[58:78]
                asc_str = asc_str.replace('"', '&quot;')
                asc_str = asc_str.replace('<', '&lt;')
                asc_str = asc_str.replace('>', '&gt;')
                html_string += '<div class="row"><span class="text-primary mono">{0}</span> \
                                <span class="text-muted mono">{1}</span> <span class="text-success mono"> \
                                {2}</span></div>'.format(off_str, hex_str, asc_str)
        # return the data
        return HttpResponse(html_string)


class YaraRulesView(LoginRequiredMixin, TemplateView):
    """Manage Yara Rules"""

    # TODO(frennkie) this depends on - not yet merged - #649
    yara_rule_path = os.path.join(__project__.base_path, 'yara')

    def yara_rule_list(self):
        # TODO(frennkie) clean this up when merging #649
        if not os.path.isdir(self.yara_rule_path):
            os.makedirs(self.yara_rule_path)
        return sorted(os.listdir(self.yara_rule_path), key=lambda y: y.lower())
    yara_rule_list = property(yara_rule_list)

    def get(self, request, *args, **kwargs):
        template_name = 'viperweb/yara.html'

        # Read Rules
        action = request.GET.get('action')
        rule = request.GET.get('rule')
        rule_text = ''

        if action == 'list' or action is None:
            return render(request, template_name, {'rule_list': self.yara_rule_list,
                                                   'rule_text': rule_text,
                                                   'projects': get_project_list()})
        elif action == 'display' and rule:
            # Display Rule Contents
            rule_file = os.path.join(self.yara_rule_path, rule)
            if os.path.isfile(rule_file):
                # Only allow .yar or .yara files to be read
                file_name, file_ext = os.path.splitext(rule_file)
                if file_ext in ['.yar', '.yara']:
                    rule_text = open(rule_file, 'r').read()
                    if not rule_text:
                        rule_text = "Empty Rule"
                else:
                    rule_text = 'Invalid Rule File'
            else:
                rule_text = 'Invalid Rules File'

        elif action == 'delete':
            rule_name = request.GET.get('rulename')
            if rule_name.split('.')[-1] in ['yar', 'yara']:
                try:
                    os.remove(os.path.join(self.yara_rule_path, rule_name))
                except FileNotFoundError:
                    raise Http404("Yara rule file not found: {}".format(rule_name))
                log.debug('Rule {0} Deleted'.format(rule_name))
                rule_text = 'Rule {0} Deleted'.format(rule_name)
            else:
                rule_text = 'Invalid Rule'
            return render(request, template_name, {'rule_list': self.yara_rule_list,
                                                   'rule_text': rule_text,
                                                   'projects': get_project_list()
                                                   })
        else:
            rule_text = 'Invalid Action'

        return render(request, template_name, {'rule_list': self.yara_rule_list,
                                               'rule_name': rule,
                                               'rule_text': rule_text,
                                               'projects': get_project_list()})

    # Modify Rules
    def post(self, request, *args, **kwargs):
        template_name = 'viperweb/yara.html'

        rule_name = request.POST.get('rule_name')
        rule_text = request.POST.get('rule_text')
        rule_file = os.path.join(self.yara_rule_path, rule_name)
        # Prevent storing files in a relative path or with a non yar extension
        rule_test = rule_name.split('.')
        if len(rule_test) == 2 and rule_test[-1] in ['yar', 'yara']:
            # if file exists overwrite
            with open(rule_file, 'w') as rule_edit:
                rule_edit.write(rule_text)
        else:
            rule_text = "The File Name did not match the style 'name.yar'"

        return render(request, template_name, {'rule_list': self.yara_rule_list,
                                               'rule_name': rule_name,
                                               'rule_text': rule_text,
                                               'projects': get_project_list()})


class AboutView(TemplateView):
    """Show a simple about page"""
    def get(self, request, *args, **kwargs):
        template_name = "viperweb/about.html"

        return render(request, template_name, {'version': __version__,
                                               'extractors': Extractor().extractors,
                                               'projects': get_project_list()})


class ChangelogView(TemplateView):
    """Show a simple changelog page"""
    def get(self, request, *args, **kwargs):
        template_name = "viperweb/changelog.html"

        _changelog = {"foo": "bar"}
        return render(request, template_name, {'changelog': _changelog,
                                               'projects': get_project_list()})


class CliView(LoginRequiredMixin, TemplateView):
    """Show GUI that implement the command line interface (CLI)"""
    def get(self, request, *args, **kwargs):
        project = kwargs.get("project", "default")
        if project not in get_project_list():
            raise Http404("unknown project: {}".format(project))

        template_name = "viperweb/cli.html"
        return render(request, template_name, {'project': project,
                                               'projects': get_project_list()})


class ConfigView(LoginRequiredMixin, TemplateView):
    """Show a simple page listing the settings from the config file"""
    def get(self, request, *args, **kwargs):
        template_name = "viperweb/config.html"

        sections = list(cfg.__dict__)
        config_values = {}
        for section in sections:
            config_values[section] = cfg.get(section)
        return render(request, template_name, {'config_values': config_values,
                                               'projects': get_project_list()})


class CreateProjectView(LoginRequiredMixin, TemplateView):
    """Create project (if not existing) and switch (redirect) to it"""
    def get(self, request, *args, **kwargs):
        return HttpResponse('This is a POST only view')

    def post(self, request, *args, **kwargs):
        project_name = request.POST['project'].replace(' ', '_')
        if project_name not in get_project_list():
            log.debug("creating new project: {}".format(project_name))

        log.debug("redirecting to project: {}".format(project_name))
        __project__.open(project_name)
        return redirect(reverse('main-page-project', kwargs={'project': project_name}))


class CuckooCheckOrSubmitView(LoginRequiredMixin, TemplateView):
    """Check if report for file exists on Cuckoo - if not submit"""
    def get(self, request, *args, **kwargs):
        project = kwargs.get('project', 'default')
        db = open_db(project)
        if project not in get_project_list():
            raise Http404("unknown project: {}".format(project))

        sha256 = kwargs.get("sha256")
        malware = db.find(key='sha256', value=sha256)
        malware_obj = malware[0]

        if not sha256:
            log.error("no sha256 hashed provided")
            raise Http404("no sha256 hashed provided")

        # Open a session
        try:
            path = get_sample_path(sha256)
            __sessions__.new(path)
        except Exception as err:
            log.error("Error: {}".format(err))
            return HttpResponse('<span class="alert alert-danger">Invalid Submission</span>'.format())

        try:
            task_list_url = '{0}/tasks/list'.format(cfg.cuckoo.cuckoo_host)
            task_list_response = requests.get(task_list_url)
            if task_list_response.status_code == 200:
                task_list = task_list_response.json()
                task_list_filtered = [x for x in task_list["tasks"] if x["sample"]["sha256"] == sha256]
                if task_list_filtered:
                    task_list_filtered_sorted = sorted(task_list_filtered, key=itemgetter("added_on"), reverse=True)
                    task_id = task_list_filtered_sorted[0]["id"]
                    ruta = '{0}/tasks/report/{1}'.format(cfg.cuckoo.cuckoo_host, str(task_id))
                    resp = requests.get(ruta)
                    json_data = resp.json()
                    db.update_malware_task(malware_obj.id, task_id, json_data)
                    return HttpResponse('<a href="{0}/analysis/{1}/summary/" target="_blank"> Enlace al último Reporte de Cukoo (Regrese a la pantalla principal y entre nuevamente para ver el reporte generado por Cuckoo en esta página)</a>'.format(cfg.cuckoo.cuckoo_web, str(task_id)))
        except Exception as err:
            log.error("Error: {}".format(err))
            return HttpResponse('<span class="alert alert-danger">Error Connecting To Cuckoo</span>'.format())

        # If it doesn't exist, submit it.

        # Get the file data from viper
        file_data = open(__sessions__.current.file.path, 'rb').read()
        file_name = __sessions__.current.file.name

        if file_data:
            # Submit file data to cuckoo
            uri = '{0}{1}'.format(cfg.cuckoo.cuckoo_host, '/tasks/create/file')
            s = malware_obj.type
            options = {'file': (file_name, file_data)}
            if s[:5] == 'PE32+':
                params = {'machine': 'W764'}
                cuckoo_response = requests.post(uri, files=options, data=params)
            else:
                params = {'machine': 'W732'}
                cuckoo_response = requests.post(uri, files=options, data=params)

            if cuckoo_response.status_code == 200:
                cuckoo_id = dict(cuckoo_response.json())['task_id']
                return HttpResponse('<a href="{0}/analysis/pending/" target="_blank"> Link To Cuckoo (pending tasks)</a>'.format(cfg.cuckoo.cuckoo_web, str(cuckoo_id)))
            else:
                log.error("Cuckoo Response Code: {}".format(cuckoo_response.status_code))

        return HttpResponse('<span class="alert alert-danger">Unable to Submit File</span>')


class SearchFileView(LoginRequiredMixin, TemplateView):
    """ Search file"""
    def get(self, request, *args, **kwargs):
        return HttpResponse('This is a POST only view')

    def post(self, request, *args, **kwargs):
        template_name = "viperweb/search_result.html"
        key = request.POST.get('key')
        value = request.POST.get('term').lower()
        cur_project = request.POST.get('cur_project', 'default')

        search_all_projects = request.POST.get('search-project-radio', 'search-this-project')
        print("projects: {}".format(search_all_projects))

        # TODO(frennkie) remove DEBUG
        print("Key: {}".format(key))
        print("Value: {}".format(value))

        if not value:
            print("no search term provided")
            messages.error(request, "no search term provided")
            return redirect(reverse("main-page-project", kwargs={"project": cur_project}))

        # Set some data holders
        results = []
        projects = []

        # Search All Projects
        if search_all_projects == "search-all-projects":
            # Get list of project paths
            projects = get_project_list()
        else:
            # If not searching all projects what are we searching
            projects.append(cur_project)

        # Search each Project in the list
        for project in projects:
            db = open_db(project)
            print(db)
            # get results
            proj_results = []
            rows = db.find(key=key, value=value)
            print(rows)

            for row in rows:
                proj_results.append([row.name, row.sha256])
            results.append({'name': project, 'res': proj_results})

        if results:
            # Return some things
            return render(request, template_name, {'results': results,
                                                   'searched_key': key,
                                                   'searched_value': value,
                                                   'projects': get_project_list()})
        else:
            return render(request, template_name, {'results': [],
                                                   'searched_key': key,
                                                   'searched_value': value,
                                                   'projects': get_project_list()})

def get_vt_value(file_hash,project,sha256):
     db = open_db(project)
     archivo = get_sample_path(file_hash)
     p = {'apikey': '92381ccfb3951b7ca464e76fc84047fefeead09cb717c0bdd6b2831166c08f2a'}
     f = {'file': (archivo,open(archivo,'rb'))}
     ruta = 'https://www.virustotal.com/vtapi/v2/file/scan'
     try:
         resp = requests.post(ruta, files=f, params=p)
         if resp.status_code == 200:
             respuesta = resp.json()
             recurso=respuesta['resource']
             permalink=respuesta['permalink']
             p2 = {'apikey': '92381ccfb3951b7ca464e76fc84047fefeead09cb717c0bdd6b2831166c08f2a','resource': recurso}
             h = {
	         "Accept-Encoding": "gzip,deflate",
	         "User-Agent": "gzip, My python requests library example client or username"
             }
             ruta1 = 'https://www.virustotal.com/vtapi/v2/file/report'
             resp2 = requests.get(ruta1, params=p2, headers=h)
             r = resp2.json()
             verbose_msg = str(r['verbose_msg'])
             resource = str(r['resource'])
             scan_id = str(r['scan_id'])
             s = str(r['scan_date'])
             f = "%Y-%m-%d %H:%M:%S"
             scan_date = datetime.strptime(s, f)
             positives = int(r['positives'])
             total = int(r['total'])
             db.add_malwarevt(sha256, scan_id, permalink, resource, verbose_msg, scan_date, positives, total)
             for scan in r['scans']:
                 dato=unicodedata.normalize('NFKD',scan).encode('ascii','ignore')
                 antivirus = dato.decode('utf-8')
                 detected = int(r['scans'][dato.decode('utf-8')]['detected'])
                 version = str(r['scans'][dato.decode('utf-8')]['version'])
                 result = str(r['scans'][dato.decode('utf-8')]['result'])
                 update = str(r['scans'][dato.decode('utf-8')]['update'])
                 db.add_malwarevtsc(sha256, antivirus, detected, version, result, update)
     except:
         print('Error de conexión')

def update_vt_value(file_hash,project,sha256):
     db = open_db(project)
     archivo = get_sample_path(file_hash)
     p = {'apikey': '92381ccfb3951b7ca464e76fc84047fefeead09cb717c0bdd6b2831166c08f2a'}
     f = {'file': (archivo,open(archivo,'rb'))}
     ruta = 'https://www.virustotal.com/vtapi/v2/file/scan'
     try:
         resp = requests.post(ruta, files=f, params=p)
         if resp.status_code == 200:
             respuesta = resp.json()
             recurso=respuesta['resource']
             p2 = {'apikey': '92381ccfb3951b7ca464e76fc84047fefeead09cb717c0bdd6b2831166c08f2a','resource': recurso}
             h = {
	         "Accept-Encoding": "gzip,deflate",
	         "User-Agent": "gzip, My python requests library example client or username"
             }
             ruta1 = 'https://www.virustotal.com/vtapi/v2/file/report'
             resp2 = requests.get(ruta1, params=p2, headers=h)
             r = resp2.json()
             verbose_msg = str(r['verbose_msg'])
             resource = str(r['resource'])
             s = str(r['scan_date'])
             f = "%Y-%m-%d %H:%M:%S"
             scan_date = datetime.strptime(s, f)
             positives = int(r['positives'])
             total = int(r['total'])
             db.update_malwarevt(resource, scan_date, positives, total)
             for scan in r['scans']:
                 dato=unicodedata.normalize('NFKD',scan).encode('ascii','ignore')
                 antivirus = dato.decode('utf-8')
                 detected = int(r['scans'][dato.decode('utf-8')]['detected'])
                 version = str(r['scans'][dato.decode('utf-8')]['version'])
                 result = str(r['scans'][dato.decode('utf-8')]['result'])
                 update = str(r['scans'][dato.decode('utf-8')]['update'])
                 db.update_malwarevtsc(sha256, antivirus, detected, version, result, update)
     except:
         print('Error de conexión')

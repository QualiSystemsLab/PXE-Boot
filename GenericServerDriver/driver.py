import subprocess
import tempfile

import time
from cloudshell.api.cloudshell_api import CloudShellAPISession
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.context import InitCommandContext, ResourceCommandContext, AutoLoadCommandContext, \
    AutoLoadAttribute, AutoLoadResource, AutoLoadDetails
from cloudshell.core.logger import qs_logger

import paramiko
import re


def powershell(script_text, error_ignore_pattern=None):
    # log_main(time.strftime('%Y-%m-%d %H:%M:%S') + ': powershell: ' + script_text.replace('\r\n', '\n') + '\n')

    logger = qs_logger.get_qs_logger()
    f = tempfile.NamedTemporaryFile(suffix='.ps1', delete=False)
    f.write(script_text.replace('\r\n', '\n'))
    f.close()
    try:
        rv = subprocess.check_output([r'c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', f.name], stderr=subprocess.STDOUT)
        if rv is not None:
            rv = rv.strip()
        logger.debug(time.strftime('%Y-%m-%d %H:%M:%S') + ': powershell result: ' + str(rv).replace('\r\n', '\n') + '\n')
        if error_ignore_pattern:
            rv = re.sub(error_ignore_pattern, '', rv)
        # if 'FullyQualifiedErrorId' in rv:
        #     raise Exception('PowerCLI error detected')
        return rv + '\nPowerCLI error detected'
    except Exception as e:
        if hasattr(e, 'output'):
            ou = str(e.output)
        else:
            ou = 'no output'
        logger.debug(time.strftime('%Y-%m-%d %H:%M:%S') + ': powershell failed: ' + str(e).replace('\r\n', '\n') + ': ' + ou.replace('\r\n', '\n') + '\n')
        return ou
        # raise e


def powercli(vcenter_ip, vcenter_user, vcenter_password, script):
    return powershell('''
$ErrorActionPreference = 'Continue'
. "C:\\Program Files (x86)\\VMware\\Infrastructure\\vSphere PowerCLI\\Scripts\\Initialize-PowerCLIEnvironment.ps1" $true
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -confirm:$false | out-null
Connect-VIServer ''' + vcenter_ip + ''' -User ''' + vcenter_user + ''' -Password ''' + vcenter_password + '''
''' + script + '''
''')


class LinuxSSH:
    def __init__(self, ip, port, user, password, logger):
        self.logger = logger
        self.ssh = paramiko.SSHClient()
        self.ssh.load_system_host_keys()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(ip,
                         port=port,
                         username=user,
                         password=password)

        self.channel = self.ssh.invoke_shell()
        self.chread('[$#]')
        self.command('PS1="QSPR""OMPT#"')

    def __del__(self):
        self.channel = None
        self.ssh.close()
        self.ssh = None

    def chread(self, prompt_regex):
        out = ''
        while True:
            r = self.channel.recv(2048)
            if r:
                out += r
            if out:
                t = out
                t = re.sub(r'[\x9b\x1b][[?;0-9]*[a-zA-Z]', '', t)
                t = re.sub(r'[\x9b\x1b][>=]', '', t)
                t = re.sub('.\b', '', t)  # *not* r'.\b'
            else:
                t = ''
            if not r or len(re.findall(prompt_regex, t)) > 0:
                out = t
                if out:
                    out = out.replace('\r', '\n')
                # self.logger.debug(re.sub('[^-a-zA-Z0-9_\n\r\t ]', '_', out))
                return out

    def chwrite(self, s):
        # self.logger.debug(re.sub('[^-a-zA-Z0-9_\n\r\t ]', '_', s))
        self.channel.send(s)

    def command(self, s):
        self.logger.debug('Command: %s\n' % s)
        self.chwrite(s + '\n')
        t = self.chread('QSPROMPT#').strip()
        if t.startswith(s):
            t = t[len(s):]
            t = t.strip()
        t = t.replace('QSPROMPT#', '')
        t = t.strip()
        self.logger.debug('Result: %s\n' % t)
        return t


def GET_VCENTER_CREDENTIALS(api, family, model, vcenter_resource_name, vmname):
    d = api.GetResourceDetails(vmname)
    if hasattr(d.VmDetails, 'CloudProviderFullName'):
        vcenter_resource_name = d.VmDetails.CloudProviderFullName

    return GET_RESOURCE_CREDENTIALS(api, 'Cloud Provider', 'VMware vCenter', vcenter_resource_name)


def GET_RESOURCE_CREDENTIALS(api, family, model, name):
    candidates = api.FindResources(family, model).Resources
    if name:
        found = False
        for pxe in candidates:
            if pxe.Name == name:
                found = True
        if not found:
            raise Exception('No %s with name "%s" found in domain' % (model, name))
    else:
        if len(candidates) == 0:
            raise Exception('There must be at least one resource of model %s in domain' % (model))
        if len(candidates) > 1:
            raise Exception(
                'Specify the resource name when there is more than one %s resource in the domain. '
                'Found resources in domain: %s' % (model, ', '.join([pxe.Name for pxe in candidates])))
        name = candidates[0].Name

    det = api.GetResourceDetails(name)

    ip = det.Address
    user = [a.Value for a in det.ResourceAttributes if a.Name == 'User'][0]
    password = api.DecryptPassword([a.Value for a in det.ResourceAttributes if a.Name == 'Password'][0]).Value

    return ip, user, password


class GenericServerDriver (ResourceDriverInterface):

    def __init__(self):
        """
        ctor must be without arguments, it is created with reflection at run time
        """
        pass

    def initialize(self, context):
        """
        Initialize the driver session, this function is called everytime a new instance of the driver is created
        This is a good place to load and cache the driver configuration, initiate sessions etc.
        :param InitCommandContext context: the context the command runs on
        """
        pass

    # def refresh_mac(self, context, vcenter_resource_name):
    #     """
    #     :param ResourceCommandContext context: the context the command runs on
    #     """
    #
    #     domain = context.reservation.domain
    #     api = CloudShellAPISession(context.connectivity.server_address,token_id=context.connectivity.admin_auth_token)
    #
    #     vmname = context.resource.name
    #
    #     vcip, vcuser, vcpassword = GET_VCENTER_CREDENTIALS(api, domain, 'Cloud Provider', 'VMware vCenter', vcenter_resource_name)
    #
    #     o = powercli(vcip, vcuser, vcpassword, '''
    #
    #     (get-vm "%s" | get-view).config.hardware.device | select MacAddress
    #     ''' % vmname)
    #
    #     macs = re.findall(r'[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]', o)
    #
    #     d = api.GetResourceDetails(vmname)
    #     for i, mac in enumerate(macs):
    #         if len(d.ChildResources) == 0:
    #             api.CreateResource('Port', 'Resource Port', 'NIC %d' % (i+1), str(i), '', vmname)
    #         api.SetAttributeValue('%s/NIC %d' % (vmname, i+1), 'MAC Address', mac)

    def smash_clp_power_cycle(self, context):
        logger = qs_logger.get_qs_logger()
        api = CloudShellAPISession(context.connectivity.server_address, token_id=context.connectivity.admin_auth_token)

        smash_ip = context.resource.attributes['SMASH CLP IP']
        smash_user = context.resource.attributes['SMASH CLP User']
        smash_password = api.DecryptPassword(context.resource.attributes['SMASH CLP Password']).Value

        ssh = LinuxSSH(smash_ip, 22, smash_user, smash_password, logger)

        ssh.command('stop /system1')
        time.sleep(5)
        ssh.command('start /system1')

    # def racadm_set_nic_boot_last(self, context):
    #     pass
    # def racadm_set_nic_boot_first(self, context):
    #     pass

    def idrac_move_nic_boot(self, context, first_last):
        logger = qs_logger.get_qs_logger()
        api = CloudShellAPISession(context.connectivity.server_address, token_id=context.connectivity.admin_auth_token)
        pxeip, pxeuser, pxepassword = GET_RESOURCE_CREDENTIALS(api, 'Server', 'PXEServer', '')

        idrac_ip = context.resource.attributes['iDRAC IP']
        idrac_user = context.resource.attributes['iDRAC User']
        idrac_password = api.DecryptPassword(context.resource.attributes['iDRAC Password']).Value

        ssh = LinuxSSH(pxeip, 22, pxeuser, pxepassword, logger)

        bootsources = []
        ssh.command('''wsman invoke -a ChangeBootOrderByInstanceID 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_BootConfigSetting?InstanceID="IPL"' -h %s -P 443 -V -v -c dummy.cert -u "%s" -p "%s" -y basic %s'''
                    % (idrac_ip, idrac_user, idrac_password, ' '.join(['-k "Source=%s"' % bootsource for bootsource in bootsources])))

        jobid = ssh.command('''wsman invoke -a CreateTargetedConfigJob 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_iDRACCardService?SystemCreationClassName="DCIM_ComputerSystem",SystemName="DCIM:ComputerSystem",CreationClassName="DCIM_iDRACCardService",Name="DCIM:iDRACCardService"' -h %s -P 443 -V -v -c dummy.cert -u "%s" -p "%s" -y basic   -k "Target=iDRAC.Embedded.1" -k "ScheduledStartTime=TIME_NOW"'''
                    % (idrac_ip, idrac_user, idrac_password)).strip()

        # jobid = ssh.command('''wsman invoke -a CreateTargetedConfigJob 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_BootConfigSetting?InstanceID="IPL"' -h %s -P 443 -V -v -c dummy.cert -u "%s" -p "%s" -y basic   -k "Target=iDRAC.Embedded.1" -k "ScheduledStartTime=TIME_NOW"'''
        #             % (idrac_ip, idrac_user, idrac_password)).strip()
        # todo parse
        # while True:
        #     status = ssh.command('''wsman get http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_LifecycleJob?InstanceID=%s -h %s -V -v -c dummy.cert -P 443 -u "%s" -p "%s"  -y basic'''
        #             % (jobid, idrac_ip, idrac_user, idrac_password))
        #     todo parse
        #     if :
        #         break
        #     time.sleep(5)

    def idrac_enable_ipmi(self, context):
        logger = qs_logger.get_qs_logger()
        api = CloudShellAPISession(context.connectivity.server_address, token_id=context.connectivity.admin_auth_token)
        pxeip, pxeuser, pxepassword = GET_RESOURCE_CREDENTIALS(api, 'Server', 'PXEServer', '')

        idrac_ip = context.resource.attributes['iDRAC IP']
        idrac_user = context.resource.attributes['iDRAC User']
        idrac_password = api.DecryptPassword(context.resource.attributes['iDRAC Password']).Value

        ssh = LinuxSSH(pxeip, 22, pxeuser, pxepassword, logger)

        ssh.command('''wsman invoke -a SetAttribute 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_iDRACCardService?SystemCreationClassName="DCIM_ComputerSystem",SystemName="DCIM:ComputerSystem",CreationClassName="DCIM_iDRACCardService",Name="DCIM:iDRACCardService"' -h %s -P 443 -V -v -c dummy.cert -u "%s" -p "%s" -y basic  -k "Target=iDRAC.Embedded.1" -k "AttributeName=IPMILan.1#Enable" -k "AttributeValue=Enabled"'''
                    % (idrac_ip, idrac_user, idrac_password))

        jobid = ssh.command('''wsman invoke -a CreateTargetedConfigJob 'http://schemas.dell.com/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_iDRACCardService?SystemCreationClassName="DCIM_ComputerSystem",SystemName="DCIM:ComputerSystem",CreationClassName="DCIM_iDRACCardService",Name="DCIM:iDRACCardService"' -h %s -P 443 -V -v -c dummy.cert -u "%s" -p "%s" -y basic   -k "Target=iDRAC.Embedded.1" -k "ScheduledStartTime=TIME_NOW"'''
                    % (idrac_ip, idrac_user, idrac_password)).strip()

        # todo parse
        # while True:
        #     ssh.command('''wsman get http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_LifecycleJob?InstanceID=%s -h %s -V -v -c dummy.cert -P 443 -u "%s" -p "%s"  -y basic'''
        #             % (jobid, idrac_ip, idrac_user, idrac_password))
        #     todo parse
        #     if :
        #         break
        #     time.sleep(5)

    def idrac_power_cycle(self, context):
        logger = qs_logger.get_qs_logger()
        api = CloudShellAPISession(context.connectivity.server_address,token_id=context.connectivity.admin_auth_token)
        pxeip, pxeuser, pxepassword = GET_RESOURCE_CREDENTIALS(api, 'Server', 'PXEServer', '')
        
        idrac_ip = context.resource.attributes['iDRAC IP']
        idrac_user = context.resource.attributes['iDRAC User']
        idrac_password = api.DecryptPassword(context.resource.attributes['iDRAC Password']).Value
        
        ssh = LinuxSSH(pxeip, 22, pxeuser, pxepassword, logger)
        ssh.command('wsman invoke -a RequestPowerStateChange '
                    '"http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_CSPowerManagementService'
                    '?CreationClassName=DCIM_CSPowerManagementService,SystemCreationClassName=DCIM_SPComputerSystem,SystemName=systemmc,Name=pwrmgtsvc:1"'
                    ' -k PowerState="8" -h %s -V -v -c dummy.cert -P 443 -u "%s" -p "%s" -j utf-8 -y basic'
                    % (idrac_ip, idrac_user, idrac_password))
        time.sleep(10)
        ssh.command('wsman invoke -a RequestPowerStateChange '
                    '"http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_CSPowerManagementService'
                    '?CreationClassName=DCIM_CSPowerManagementService,SystemCreationClassName=DCIM_SPComputerSystem,SystemName=systemmc,Name=pwrmgtsvc:1"'
                    ' -k PowerState="2" -h %s -V -v -c dummy.cert -P 443 -u "%s" -p "%s" -j utf-8 -y basic'
                    % (idrac_ip, idrac_user, idrac_password))

    def ipmi_power_cycle(self, context):
        logger = qs_logger.get_qs_logger()
        api = CloudShellAPISession(context.connectivity.server_address,token_id=context.connectivity.admin_auth_token)
        pxeip, pxeuser, pxepassword = GET_RESOURCE_CREDENTIALS(api, 'Server', 'PXEServer', '')

        ipmi_ip = context.resource.attributes['IPMI IP']
        ipmi_user = context.resource.attributes['IPMI User']
        ipmi_password = api.DecryptPassword(context.resource.attributes['IPMI Password']).Value

        ssh = LinuxSSH(pxeip, 22, pxeuser, pxepassword, logger)
        ssh.command('ipmitool -H %s -v -I lanplus -U "%s" -P "%s" chassis bootdev pxe' % (ipmi_ip, ipmi_user, ipmi_password))
        ssh.command('ipmitool -H %s -v -I lanplus -U "%s" -P "%s" chassis power off' % (ipmi_ip, ipmi_user, ipmi_password))
        time.sleep(5)
        ssh.command('ipmitool -H %s -v -I lanplus -U "%s" -P "%s" chassis power on' % (ipmi_ip, ipmi_user, ipmi_password))


    def configure_pxe_boot(self, context, os_name, pxe_server_resource_name):
        """
        :param ResourceCommandContext context: the context the command runs on
        :param str os_name: OS to deploy, Windows7, CentOS6, CentOS7, CentOS7min, ESXi
        :param str pxe_server_resource_name: optional name of PXE server resource
        """
        logger = qs_logger.get_qs_logger()

        # logger.info('XXXX: ' + str(vars(context.connectivity)))
        # logger.info('XXXX: ' + str(vars(context.reservation)))
        # logger.info('XXXX: ' + str(vars(context.resource)))

        api = CloudShellAPISession(context.connectivity.server_address,token_id=context.connectivity.admin_auth_token)

        servername = context.resource.name

        mac = ''
        for ch in api.GetResourceDetails(servername).ChildResources:
            mac = [a.Value for a in ch.ResourceAttributes if a.Name == 'MAC Address'][0]
            break
        if not mac:
            raise Exception('Resource "%s" must have a NIC subresource and MAC Address must be set on it' % servername)

        pxeip, pxeuser, pxepassword = GET_RESOURCE_CREDENTIALS(api, 'Server', 'PXEServer', pxe_server_resource_name)

        ssh = LinuxSSH(pxeip, 22, pxeuser, pxepassword, logger)

        osname2imagename = {
            'Windows7': 'defaultwin7',
            'CentOS6': 'default6',
            'CentOS7': 'default7',
            'CentOS7min': 'default7min',
            'ESXi': 'defaultesxi',
        }

        if os_name not in osname2imagename:
            raise Exception(
                'OS name "%s" not found. Possible values are %s' % (os_name, sorted(osname2imagename.keys())))

        imagename = osname2imagename[os_name]

        ssh.command('cp /var/www/html/pxelinux.cfg/%s /var/www/html/pxelinux.cfg/01-%s' % (
            imagename, mac.replace(':', '-').lower()))

    def unconfigure_pxe_boot(self, context, os_name, pxe_server_resource_name):
        """
        :param ResourceCommandContext context: the context the command runs on
        :param str os_name: OS to deploy, Windows7, CentOS6, CentOS7, CentOS7min, ESXi
        :param str pxe_server_resource_name: optional name of PXE server resource
        """
        logger = qs_logger.get_qs_logger()

        # logger.info('XXXX: ' + str(vars(context.connectivity)))
        # logger.info('XXXX: ' + str(vars(context.reservation)))
        # logger.info('XXXX: ' + str(vars(context.resource)))

        api = CloudShellAPISession(context.connectivity.server_address,token_id=context.connectivity.admin_auth_token)

        servername = context.resource.name

        mac = ''
        for ch in api.GetResourceDetails(servername).ChildResources:
            mac = [a.Value for a in ch.ResourceAttributes if a.Name == 'MAC Address'][0]
            break
        if not mac:
            raise Exception('Resource "%s" must have a NIC subresource and MAC Address must be set on it' % servername)

        pxeip, pxeuser, pxepassword = GET_RESOURCE_CREDENTIALS(api, 'Server', 'PXEServer', pxe_server_resource_name)

        ssh = LinuxSSH(pxeip, 22, pxeuser, pxepassword, logger)

        ssh.command('rm -v -f /var/www/html/pxelinux.cfg/01-%s' % (mac.replace(':', '-').lower()))


    # <editor-fold desc="Orchestration Save and Restore Standard">
    def orchestration_save(self, context, cancellation_context, mode, custom_params=None):
        """
        Saves the Shell state and returns a description of the saved artifacts and information
        This command is intended for API use only by sandbox orchestration scripts to implement
        a save and restore workflow
        :param ResourceCommandContext context: the context object containing resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str mode: Snapshot save mode, can be one of two values 'shallow' (default) or 'deep'
        :param str custom_params: Set of custom parameters for the save operation
        :return: SavedResults serialized as JSON
        :rtype: OrchestrationSaveResult
        """

        # See below an example implementation, here we use jsonpickle for serialization,
        # to use this sample, you'll need to add jsonpickle to your requirements.txt file
        # The JSON schema is defined at: https://github.com/QualiSystems/sandbox_orchestration_standard/blob/master/save%20%26%20restore/saved_artifact_info.schema.json
        # You can find more information and examples examples in the spec document at https://github.com/QualiSystems/sandbox_orchestration_standard/blob/master/save%20%26%20restore/save%20%26%20restore%20standard.md
        '''
        # By convention, all dates should be UTC
        created_date = datetime.datetime.utcnow()

        # This can be any unique identifier which can later be used to retrieve the artifact
        # such as filepath etc.

        # By convention, all dates should be UTC
        created_date = datetime.datetime.utcnow()

        # This can be any unique identifier which can later be used to retrieve the artifact
        # such as filepath etc.
        identifier = created_date.strftime('%y_%m_%d %H_%M_%S_%f')

        orchestration_saved_artifact = OrchestrationSavedArtifact('REPLACE_WITH_ARTIFACT_TYPE', identifier)

        saved_artifacts_info = OrchestrationSavedArtifactInfo(
            resource_name="some_resource",
            created_date=created_date,
            restore_rules=OrchestrationRestoreRules(requires_same_resource=True),
            saved_artifact=orchestration_saved_artifact)

        return OrchestrationSaveResult(saved_artifacts_info)
        '''
        pass

    def orchestration_restore(self, context, cancellation_context, saved_details):
        """
        Restores a saved artifact previously saved by this Shell driver using the orchestration_save function
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str saved_details: A JSON string representing the state to restore including saved artifacts and info
        :return: None
        """
        '''
        # The saved_details JSON will be defined according to the JSON Schema and is the same object returned via the
        # orchestration save function.
        # Example input:
        # {
        #     "saved_artifact": {
        #      "artifact_type": "REPLACE_WITH_ARTIFACT_TYPE",
        #      "identifier": "16_08_09 11_21_35_657000"
        #     },
        #     "resource_name": "some_resource",
        #     "restore_rules": {
        #      "requires_same_resource": true
        #     },
        #     "created_date": "2016-08-09T11:21:35.657000"
        #    }

        # The example code below just parses and prints the saved artifact identifier
        saved_details_object = json.loads(saved_details)
        return saved_details_object[u'saved_artifact'][u'identifier']
        '''
        pass

    # </editor-fold>


    # <editor-fold desc="Discovery">

    def get_inventory(self, context):
        """
        Discovers the resource structure and attributes.
        :param AutoLoadCommandContext context: the context the command runs on
        :return Attribute and sub-resource information for the Shell resource you can return an AutoLoadDetails object
        :rtype: AutoLoadDetails
        """
        # See below some example code demonstrating how to return the resource structure
        # and attributes. In real life, of course, if the actual values are not static,
        # this code would be preceded by some SNMP/other calls to get the actual resource information
        '''
           # Add sub resources details
           sub_resources = [ AutoLoadResource(model ='Generic Chassis',name= 'Chassis 1', relative_address='1'),
           AutoLoadResource(model='Generic Module',name= 'Module 1',relative_address= '1/1'),
           AutoLoadResource(model='Generic Port',name= 'Port 1', relative_address='1/1/1'),
           AutoLoadResource(model='Generic Port', name='Port 2', relative_address='1/1/2'),
           AutoLoadResource(model='Generic Power Port', name='Power Port', relative_address='1/PP1')]


           attributes = [ AutoLoadAttribute(relative_address='', attribute_name='Location', attribute_value='Santa Clara Lab'),
                          AutoLoadAttribute('', 'Model', 'Catalyst 3850'),
                          AutoLoadAttribute('', 'Vendor', 'Cisco'),
                          AutoLoadAttribute('1', 'Serial Number', 'JAE053002JD'),
                          AutoLoadAttribute('1', 'Model', 'WS-X4232-GB-RJ'),
                          AutoLoadAttribute('1/1', 'Model', 'WS-X4233-GB-EJ'),
                          AutoLoadAttribute('1/1', 'Serial Number', 'RVE056702UD'),
                          AutoLoadAttribute('1/1/1', 'MAC Address', 'fe80::e10c:f055:f7f1:bb7t16'),
                          AutoLoadAttribute('1/1/1', 'IPv4 Address', '192.168.10.7'),
                          AutoLoadAttribute('1/1/2', 'MAC Address', 'te67::e40c:g755:f55y:gh7w36'),
                          AutoLoadAttribute('1/1/2', 'IPv4 Address', '192.168.10.9'),
                          AutoLoadAttribute('1/PP1', 'Model', 'WS-X4232-GB-RJ'),
                          AutoLoadAttribute('1/PP1', 'Port Description', 'Power'),
                          AutoLoadAttribute('1/PP1', 'Serial Number', 'RVE056702UD')]

           return AutoLoadDetails(sub_resources,attributes)
        '''
        # vmname = context.resource.name
        #
        # api = CloudShellAPISession(context.connectivity.server_address,token_id=context.connectivity.admin_auth_token)
        # vcip, vcuser, vcpassword = GET_VCENTER_CREDENTIALS(api, 'Cloud Provider', 'VMware vCenter', None, vmname)
        #
        # o = powercli(vcip, vcuser, vcpassword, '''
        #
        # (get-vm "%s" | get-view).config.hardware.device | select MacAddress
        # ''' % vmname)
        #
        # macs = re.findall(
        #     r'[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]',
        #     o)
        #
        # def MAKERESOURCE(model, name, addr, uniqueid=None):
        #     rv = AutoLoadResource()
        #     rv.name = name
        #     rv.model = model
        #     rv.relative_address = addr
        #     rv.unique_identifier = uniqueid
        #     return rv
        #
        # def MAKEATTR(addr, name, value):
        #     rv = AutoLoadAttribute()
        #     rv.relative_address = addr
        #     rv.attribute_name = name
        #     rv.attribute_value = value
        #     return rv

        sub_resources = []
        attributes = []
        # for i, mac in enumerate(macs):
        #     sub_resources.append(MAKERESOURCE('Resource Port', 'NIC %d' % (i+1), str(i+1)))
        #     attributes.append(MAKEATTR(str(i+1), 'MAC Address', mac))

        rv = AutoLoadDetails()
        rv.attributes = attributes
        rv.resources = sub_resources
        return rv

    # </editor-fold>
    # def connect_child_resources(self, context):
    #     osname = context.resource.attributes['OS Image']
    #
    #     self.configure_pxe_boot(context, osname, None)


    # <editor-fold desc="Health Check">

    def health_check(self, cancellation_context):
        """
        Checks if the device is up and connectable
        :return: None
        :exception Exception: Raises an error if cannot connect
        """
        pass

    # </editor-fold>


    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass
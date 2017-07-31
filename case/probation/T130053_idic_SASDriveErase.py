from case.CBaseCase import *
from lib.Apps import dhcp_query_ip
import gevent

PROMPT_GUEST = "infrasim@root:~$"
CONF = {}
class T130053_idic_SASDriveErase(CBaseCase):
    '''
    [Purpose ]: Test SAS drive erase in Ubuntu 16.04 host OS with sg_utils tools.
    [Author  ]: june.zhou@emc.com
    '''
    def __init__(self):
        CBaseCase.__init__(self, self.__class__.__name__)

    def config(self):
        CBaseCase.config(self)
        self.enable_node_ssh()

        if not os.path.isfile(os.environ["HOME"]+"/images/ubuntu16.04_2.qcow2"):
            self.log('INFO', "No ubuntu image for test.")
            raise Exception('No ubuntu image not found. Please put one in folder \'~/images/\'')

    def test(self):
        gevent.joinall([gevent.spawn(self.boot_to_disk, obj_node)
                        for obj_node in self.stack.walk_node()])
        gevent.joinall([gevent.spawn(self.sas_drive_erase, obj_node)
                        for obj_node in self.stack.walk_node()])

    def deconfig(self):
        # To do: Case specific deconfig
        CBaseCase.deconfig(self)

    def update_node_config(self, node):
        # Update node config
        #dst_path = node.send_file(os.environ["HOME"]+"/images/ubuntu16.04_2.qcow2", "/tmp/ubuntu16.04_2.qcow2")
        dst_path = "/tmp/ubuntu16.04_2.qcow2"
        str_node_name = node.get_instance_name()

        payload = [
            {
                "type": "ahci",
                "max_drive_per_controller": 6,
                "drives": [{"bootindex":1, "size": 8, "file": dst_path}]
            },
            {
                "type": "ahci", #to change to lsisas3008 after qemu lsi code merge in
                "max_drive_per_controller":6,
                "drives": [{"size": 8,
                            "format": "raw",
                            "serial": "20160518AA851134100",
                            "file": "/tmp/sdb.img"}]
            },
            {
                "type": "megasas-gen2", #to change to lsisas3008 after qemu lsi code merge in
                "max_drive_per_controller":6,
                "drives": [{"size": 8,
                            "format": "raw",
                            "serial": "20160518AA851134101",
                            "file": "/tmp/sdc.img"}]
            },

        ]
        node.update_instance_config(str_node_name, payload, "compute", "storage_backend")

        payload = {
                "size":4096
        }

        node.update_instance_config(str_node_name, payload, "compute", "memory")

        payload = {
                "features":"+vmx"
        }

        node.update_instance_config(str_node_name, payload, "compute", "cpu")

        node.update_instance_config(str_node_name, "e1000", "compute", "networks", 0, "device")
        node.update_instance_config(str_node_name, "bridge", "compute", "networks", 0, "network_mode")
        node.update_instance_config(str_node_name, "br0", "compute", "networks", 0, "network_name")

    def boot_to_disk(self, node):
        self.update_node_config(node)
        # Set boot order to hard disk
        self.log('INFO', 'Set next boot option to disk on {}...'.format(node.get_name()))
        ret, rsp = node.get_bmc().ipmi.ipmitool_standard_cmd("chassis bootdev disk")
        if ret != 0:
            self.result(BLOCK, "Fail to set instance {} on {} boot from disk".
                        format(str_node_name, node.get_ip()))

        str_node_name = node.get_instance_name()

        # Reboot to ubuntu img
        self.log('INFO', 'Power cycle guest to boot to disk on {}...'.format(node.get_name()))
        ret, rsp = node.get_bmc().ipmi.ipmitool_standard_cmd("chassis power cycle")
        if ret != 0:
            self.result(BLOCK, "Fail to set instance {} on {} boot from disk".
                        format(str_node_name, node.get_ip()))
            return

        time.sleep(5)

        # Get qemu IP
        str_node_name = node.get_instance_name()
        qemu_config = node.get_instance_config(str_node_name)
        qemu_first_mac = qemu_config["compute"]["networks"][0]["mac"].lower()
        
        rsp = node.ssh.send_command_wait_string(str_command=r"arp -e | grep {} | awk '{{print $1}}'".
                                                format(qemu_first_mac)+chr(13),
                                                wait="~$")
        qemu_first_ip = rsp.splitlines()[1]
        if not is_valid_ip(qemu_first_ip):
            # If fail to get IP via arp, try to query via dhcp lease
            try:
                qemu_first_ip = self.get_guest_ip(qemu_first_mac)
            except:
                self.result(BLOCK, "Fail to get virtual compute IP address on {} {}".
                            format(node.get_name(), node.get_ip()))
                return
            else:
                self.log("INFO", "Guest IP is {} on node {}".format(qemu_first_ip, node.get_name()))
        # SSH to guest
        node.ssh.send_command_wait_string(str_command="ssh {}@{}".format(self.data['host_username'], qemu_first_ip)
                                         +chr(13), wait=["(yes/no)", "password"])
        match_index = node.ssh.get_match_index()
        if match_index == 0:
            self.result(BLOCK, "Fail to ssh to guest on {} {}".
                        format(node.get_name(), node.get_ip()))
            return
        elif match_index == 1:
            node.ssh.send_command_wait_string(str_command="yes"+chr(13),
                                              wait="password")
        node.ssh.send_command_wait_string(str_command=self.data['host_password']+chr(13),
                                          wait=PROMPT_GUEST)


    def get_sas_drives(self, node):
        # Find SAS drives
        rsp = node.ssh.send_command_wait_string(str_command='ls /dev'+chr(13),
                                                wait=PROMPT_GUEST)
        drives = [e.replace("\x1b[0m", "").replace("\x1b[40;33;01m", "") \
                 for e in filter(lambda x:"sd" in x, rsp.split())]

        sas_drives = []
        for drive in drives:
            drive_info = node.ssh.send_command_wait_string(str_command='echo "'+
                                                          self.data['host_password']+
                                                          '" | sudo -S sg_inq /dev/'+drive+chr(13),
                                                          wait=PROMPT_GUEST)

            if "Vendor identification: ATA" not in drive_info:
                sas_drives.append(drive)

        self.log('INFO', 'SAS drives: \n{}'.format(''.join(sas_drives)))
        return sas_drives

    def sas_drive_erase(self, node):
        # Create data file
        node.ssh.send_command_wait_string(str_command='echo abcdefg > test_file'+chr(13),
                                                wait=PROMPT_GUEST)
        drives = self.get_sas_drives(node)

        for drive in drives:
            # Copy file to drive
            self.log('INFO', 'dd if=test_file of=/dev/{}'.format(drive))
            node.ssh.send_command_wait_string(str_command='echo "'+self.data['host_password']+
                                             '"| sudo -S dd if=test_file of=/dev/'+drive+chr(13),
                                                wait=PROMPT_GUEST)
            rsp = node.ssh.send_command_wait_string(str_command='echo "'+self.data['host_password']+
                                                    '" | sudo -S hexdump /dev/'+drive+chr(13),
                                                    wait=PROMPT_GUEST)
            
	    # Check drive data
            self.log('INFO', 'Hex dump result before formating: \n{}'.format(rsp))

            # Format drive
            rsp = node.ssh.send_command_wait_string(str_command='echo "'+self.data['host_password']+
                                                    '" | sudo -S sg_format --format /dev/'+drive+chr(13),
                                                    wait=PROMPT_GUEST)
            self.log('INFO', rsp)
            rsp = node.ssh.send_command_wait_string(str_command='echo "'+self.data['host_password']+
                                                    '" | sudo -S sg_requests -p /dev/'+drive+chr(13),
                                                    wait=PROMPT_GUEST)
            self.log('INFO', rsp)
            if "Progress indication" in rsp:
                self.result(FAIL, 'Drive format doesn\'t finish as expected. '
                           'The sg_resquests command shows format is still in progress.')
            rsp = node.ssh.send_command_wait_string(str_command='echo "'+self.data['host_password']+
                                                    '" | sudo -S hexdump /dev/'+drive+chr(13),
                                                    wait=PROMPT_GUEST)
            self.log('INFO', 'Hex dump result after formating: \n{}'.format(rsp))
            rsp = rsp.split("\n")

            if not (rsp[1]== "0000000 0000 0000 0000 0000 0000 0000 0000 0000\r" and
                    rsp[2] =="*\r" and len(rsp)==5):
                        drive_info = node.ssh.send_command_wait_string(str_command='echo "'+
                                                                      self.data['host_password']+
                                                                     '" | sudo -S sg_inq /dev/'+drive+chr(13),
                                                    wait=PROMPT_GUEST)
                        self.result(FAIL, 'SAS Drive format fails. \nNode name: {}\nNode IP: {}\nDrive info:\n'
                                    '/dev/{}\n{}\nHexdump result after format is: {} \n'.
                                    format(node.get_name(), node.get_ip(), drive, drive_info, rsp))
    
    def get_guest_ip(self, str_mac):
        DHCP_SERVER = self.data["DHCP_SERVER"]
        DHCP_USERNAME = self.data["DHCP_USERNAME"]
        DHCP_PASSWORD = self.data["DHCP_PASSWORD"]

        self.log('INFO', 'Query IP for MAC {} from DHCP server'.format(str_mac))

        time_start = time.time()
        guest_ip = ''
        while time.time() - time_start < 300:
            try:
                guest_ip = dhcp_query_ip(server=DHCP_SERVER,
                                         username=DHCP_USERNAME,
                                         password=DHCP_PASSWORD,
                                         mac=str_mac)
                rsp = os.system('ping -c 1 {}'.format(guest_ip))
                if rsp != 0:
                    self.log('INFO', 'Find an IP {} lease for MAC {}, but this IP is not online'.
                             format(guest_ip, str_mac))
                    time.sleep(30)
                    continue
                else:
                    self.log('INFO', 'Find an IP {} lease for MAC {}, this IP works'.
                             format(guest_ip, str_mac))
                    break
            except:
                self.log('WARNING', 'Fail to query IP for MAC {}'.format(str_mac))

        if not guest_ip:
            raise Exception('Fail to get IP for MAC {} in 300s'.format(str_mac))
        else:
            return guest_ip


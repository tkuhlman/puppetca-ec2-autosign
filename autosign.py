#!/usr/bin/env python
import ConfigParser
import subprocess
import sys

from boto.ec2 import connect_to_region

CONFIG_LOCATION = '/etc/puppetca-ec2-autosign.conf'
PUPPETCA = '/usr/sbin/puppetca'

def sign(csr_name):
    """Authorises the CSR for the passed host."""
    cmd = subprocess.Popen([PUPPETCA, '--sign', csr_name], stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    out, err = cmd.communicate()
    return out

def list_csrs():
    """Returns a list of all outstanding CSRs."""
    cmd = subprocess.Popen([PUPPETCA, '--list'], stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    out, err = cmd.communicate()
    csrs = out.split('\n')
    return [r for r in csrs if r]

def verify(csr_name, tag, instances):
    """Verify the host should be granted the CSR. Do this by checking the hostname matches the
        specified tag for a valid and running EC2 instance."""
    for instance in instances.itervalues():
        if instance.state != 'running':
            continue
        if instance.tags.has_key(tag) and instance.tags[tag] == csr_name:
            return True

    return False

if __name__ == '__main__':
    config = ConfigParser.ConfigParser()
    config.read(CONFIG_LOCATION)
    
    for region in config.get('aws', 'regions').split(','):
        ec2 = connect_to_region(
            aws_access_key_id=config.get('aws', 'access_key'),
            aws_secret_access_key=config.get('aws', 'secret_key'),
            region_name=region
        )
        
        outstanding_csrs = list_csrs()
        if outstanding_csrs:
            reservations = ec2.get_all_instances()
            _instances = [i for r in reservations for i in r.instances]
            instances = {}
            for i in _instances:
                instances[i.id] = i
            
            for csr in outstanding_csrs:
                if verify(csr, config.get('aws', 'tag'), instances):
                    sign(csr)
    
    sys.exit(0)

#!/usr/bin/python


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: azure_rm_vnetpeering

short_description: Create peering between Azure Virtual Networks

version_added: "2.4"

description:
    - "Setup Azure Virtual Network Peering between virtualnetworks in resourcegroups"

options:
    Resourcegroup1:
        description:
            - This is the resource group of the first virtual network that needs to be peered
        required: true
    Resourcegroup2:
        description:
            - This is the resource group of the second virtual network that needs to be peered
        required: true
    Virtualnetwork1:
        description:
            - This is the first virtual network to setup Azure Vnet Peering
        required: true
    Virtualnetwork2:
        description:
            - This is the second virtual network to setup Azure Vnet Peering
        required: true
    State:
        description:
            - This is the second virtual network to setup Azure Vnet Peering
        required: false

extends_documentation_fragment:
    - azure

author:
    - wstinkens
'''

EXAMPLES = '''
# Create Peering between 2 Azure Virtual Networks
- name: Create Vnet Peering
  azure_rm_vnetpeering:
    Resourcegroup1: foo_rg
    Resourcegroup2: bar_rg
    Virtualnetwork1: foo_vnet
    Virtualnetwork2: bar_vnet

# Delete Peering between 2 Azure Virtual Networks
- name: Delete Vnet Peering
  azure_rm_vnetpeering:
    Resourcegroup1: foo_rg
    Resourcegroup2: bar_rg
    Virtualnetwork1: foo_vnet
    Virtualnetwork2: bar_vnet
    State: absent
'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    type: str
message:
    description: The output message that the sample module generates
'''

from ansible.module_utils.basic import AnsibleModule
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import SubResource
from azure.mgmt.network.models import VirtualNetworkPeering
from azure.mgmt.resource import ResourceManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from os.path import expanduser
import configparser

credentialfile = (expanduser("~")) + "/.azure/credentials"

def get_azurecredentials(module, result):
    try:
        config = configparser.ConfigParser()
        config.read(credentialfile)
        var_subscriptionid = str(config['default']['subscription_id'])
        var_clientid = config['default']['client_id']
        var_secret = config['default']['secret']
        var_tenant = config['default']['tenant']
    except KeyError as e:
        module.fail_json(msg="failed to get Azure redentials: " + e.message, **result)

    return var_subscriptionid, var_clientid, var_secret, var_tenant

def get_azurevnetpeering(rg1, rg2, vnet1, vnet2, peering1, peering2, module, result):
    credentialvars=get_azurecredentials(module, result)
    credentials = ServicePrincipalCredentials(client_id=(credentialvars[1]), secret=credentialvars[2], tenant=credentialvars[3])
    network_client = NetworkManagementClient(credentials, credentialvars[0])
    peering1result = None
    peering2result = None

    try:
        peering1result=network_client.virtual_network_peerings.get(rg1, vnet1, peering1)
        peering2result=network_client.virtual_network_peerings.get(rg2, vnet2, peering2)
    except Exception as e:
        #module.fail_json(msg="Error: Failed to get Azure Vnet Peering: " + e.message, **result)
        print("Error: Failed to get Azure Vnet Peering: " + e.message)
            
    if (peering1result is not None) or (peering2result is not None):
        return peering1result, peering2result

def delete_azurevnetpeering(rg1, rg2, vnet1, vnet2, peering1, peering2, module, result):
    credentialvars=get_azurecredentials(module, result)
    credentials = ServicePrincipalCredentials(client_id=(credentialvars[1]), secret=credentialvars[2], tenant=credentialvars[3])
    network_client = NetworkManagementClient(credentials, credentialvars[0])

    try:
        network_client.virtual_network_peerings.delete(rg1, vnet1, peering1)
        network_client.virtual_network_peerings.delete(rg2, vnet2, peering2)
    except Exception as e:
        module.fail_json(msg="Error: Failed to delete Azure Vnet Peering: " + e.message, **result)

def create_azurevnetpeering(rg1, rg2, vnet1, vnet2, peering1, peering2, module, result):
    try:
        credentialvars=get_azurecredentials(module, result)
        credentials = ServicePrincipalCredentials(client_id=(credentialvars[1]), secret=credentialvars[2], tenant=credentialvars[3])
        resource_client = ResourceManagementClient(credentials, credentialvars[0])
        network_client = NetworkManagementClient(credentials, credentialvars[0])
    except Exception as e:
        module.fail_json(msg="Error: Failed to get Azure Credentials: " + e.message, **result)

    try:
        resource_client = ResourceManagementClient(credentials, credentialvars[0])
        network_client = NetworkManagementClient(credentials, credentialvars[0])
    except Exception as e:
        module.fail_json(msg="Error: Failed to create Azure clients: " + e.message, **result)
    
    try:
        res1 = resource_client.resources.get(rg1, "Microsoft.Network", "", "virtualNetworks", vnet1, "2017-06-01")
        res2 = resource_client.resources.get(rg2, "Microsoft.Network", "", "virtualNetworks", vnet2, "2017-06-01")
    except Exception as e:
        module.fail_json(msg="Error: Failed to get Azure Virtual Network: " + e.message, **result)

    subres1 = SubResource(id=res1.id)
    subres2 = SubResource(id=res2.id)

    peering_params1 =  VirtualNetworkPeering(allow_virtual_network_access=True, use_remote_gateways=False, remote_virtual_network=subres1)
    peering_params2 =  VirtualNetworkPeering(allow_virtual_network_access=True, use_remote_gateways=False, remote_virtual_network=subres2)

    try:
        network_client.virtual_network_peerings.create_or_update(rg2, vnet2, (peering2), peering_params1)
        network_client.virtual_network_peerings.create_or_update(rg1, vnet1, (peering1), peering_params2)
    except Exception as e:
        module.fail_json(msg="Error: Failed to create Azure Vnet Peering: " + e.message, **result)

def run_module():
    module_args = dict(
        resourcegroup1=dict(type='str', required=True),
        resourcegroup2=dict(type='str', required=True),
        virtualnetwork1=dict(type='str', required=True),
        virtualnetwork2=dict(type='str', required=True),
        state=dict(type='str', required=False, default='present')
    )

    result = dict(
        changed=False,
        peeringname1='',
        peeringname2='',
        state=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    state=module.params['state']
    rg1 = module.params['resourcegroup1']
    rg2 = module.params['resourcegroup2']
    vnet1= module.params['virtualnetwork1']
    vnet2= module.params['virtualnetwork2']
    peering1= vnet1 + "-" + vnet2 + "-peering"
    peering2= vnet2 + "-" + vnet1 + "-peering"

    if state == "present":
        peering_result = get_azurevnetpeering(rg1, rg2, vnet1, vnet2, peering1, peering2, module, result)

        if peering_result is None:
            create_azurevnetpeering(rg1, rg2, vnet1, vnet2, peering1, peering2, module, result)
            result['changed'] = True
            result['peeringname1'] = peering1
            result['peeringname2'] = peering2
            result['state'] = state
            module.exit_json(**result)
        else:
            result['peeringname1'] = peering1
            result['peeringname2'] = peering2
            result['state'] = state
            module.exit_json(**result)
    elif state == "absent":
        delete_azurevnetpeering(rg1, rg2, vnet1, vnet2, peering1, peering2, module, result)
        result['changed'] = True
        result['state'] = state
        module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
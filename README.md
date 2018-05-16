# iac-azure-ansible

Deploy an Infrastructure As Code setup on Azure with Ansible

## Create Azure Service Principel

Use the Azure CLI and execute the following command

```sh
az ad sp create-for-rbac --name ServicePrincipalName
```

## Create Credentials File

When working in a development environment, it may be desirable to store credentials in a file. The modules will look for credentials in $HOME/.azure/credentials. This file is an ini style file. It will look as follows:

```sh
[default]
subscription_id=xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
client_id=xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
secret=xxxxxxxxxxxxxxxxx
tenant=xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

## Install Ansible Roles

```sh
cd roles
ansible-galaxy install -r requirements.yml
```
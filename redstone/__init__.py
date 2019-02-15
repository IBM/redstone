
from redstone import client


services = {
    "kms": client.KeyProtect,
    "rc": client.ResourceController,
    "iks": client.IKS
}


def client(service_name, **kwargs):
    cls =  services.get(service_name)
    if not cls:
        raise ValueError("No client for service '%s'" % service_name)
    return cls(**kwargs)

from codes import ERROR, SPAWNER_SETUP, CREATING, \
    REQUESTED, DELETING
from models_pods import Pod, Password, PodBaseFull
from models_templates_tags import TemplateTag, TemplateTagPodDefinition, derive_template_info
from kubernetes_utils import create_pod, create_service, create_pvc, KubernetesError
from kubernetes import client, config

from tapisservice.config import conf
from tapisservice.logs import get_logger
from tapisservice.errors import BaseTapisError
from volume_utils import get_nfs_ip
import re

logger = get_logger(__name__)

# k8 client creation
config.load_incluster_config()
k8 = client.CoreV1Api()


def combine_pod_and_template_recursively(input_obj, template_name, seen_templates=None, tenant: str = None, site: str = None):
    """
    --- run with
    pod = Pod.db_get_with_pk(pk_id='testingfastapi', tenant='dev', site='tacc')
    d = combine_pod_and_template_recursively(pod, "template21:car@2024-06-11-18:09:39")
    d.description
    """
    if seen_templates is None:
        seen_templates = set()

    if template_name:
        if template_name in seen_templates:
            raise ValueError(f"Infinite loop detected: template {template_name} is referenced more than once in template waterfal.")
        seen_templates.add(template_name)

        template_name_str, template, template_tag = derive_template_info(template_name, tenant, site)
        modified_fields = get_modified_template_fields(TemplateTagPodDefinition().dict(), template_tag.pod_definition)

        # First, recursively combine the input_obj with the next template in the chain
        input_obj = combine_pod_and_template_recursively(input_obj, modified_fields.get('template'), seen_templates, tenant, site)

        # Then, apply the current template to the input_obj
        try:
            for mod_key, mod_val in modified_fields.items():
                if mod_key.startswith("resources."):
                    logger.critical('hey')
                    outer_arg, inner_arg = resources.split('.') # resources.gpus
                    outer_obj = getattr(input_obj, outer_arg) # resources
                    logger.critical('oh no!')
                    new_obj_value = template_tag.pod_definition[outer_arg][inner_arg]
                    setattr(outer_obj, inner_arg, new_obj_value)
                elif mod_key == "networking":
                    # must take template3, update with template2, template,1 and then pod, in that order
                    # Preserving order of objs, pod being the most important.
                    final_network_obj = getattr(input_obj, mod_key)
                    for network_name, network_def in template_tag.pod_definition[mod_key].items():                    
                        final_network_obj.update({network_name: network_def})
                    setattr(input_obj, mod_key, final_network_obj)
                elif mod_key.startswith("volume_mount."):
                    print('dog')
                elif mod_key.startswith("template"):
                    pass ## Don't need this one
                elif mod_key in input_obj.modified_fields:
                    pass ## Don't modify user-modified fields, sans the above as they're dict updates and not overwrites
                else:
                    setattr(input_obj, mod_key, mod_val)

            if input_obj.resources:
                input_obj.resources = input_obj.resources.dict()

        except Exception as e:
            logger.debug(f'Got exception when attempting to combine pod and templates: {e}')

    return input_obj


def get_modified_template_fields(original_template, modified_template_def):
    """
    Returns a dictionary of fields that have been modified from a base template
    Meaning, returns fields that user defined in template.
    """
    changed_fields = {}
    for key, value in original_template.items():
        if key not in modified_template_def or value != modified_template_def[key]:
            changed_fields[key] = modified_template_def[key]
    if changed_fields.get('resources'):
        ### resources.gpus, resources.mem_Limit, etc exists.
        # Only return resources in dict if subfield not null, so we delete null subfields
        for resource_key, resource_val in changed_fields['resources'].copy().items():
            if resource_val is None:
                del changed_fields['resources'][resource_key]
    return changed_fields


### This is quite an important function
def start_generic_pod(input_pod, revision: int):
    ###
    ### Templates
    ###
    # This all is needed as I need an object that can validate (PodBaseFull)
    # And I need template or non-template pods to have the same fields. get_with_pk returns complete dict
    # PodBaseFull returns dict with Pydantic models as vals. This forces both cases to work the same.
    pod = PodBaseFull(**input_pod.dict().copy()) # Create a copy of pod data we'll merge template data into
    logger.debug(f"Attempting to start generic pod; name: {pod.k8_name}; revision: {revision}")

    if pod.template:
        # Derive the final pod object by combining the pod and templates
        final_pod = combine_pod_and_template_recursively(pod, pod.template, tenant=pod.tenant_id, site=pod.site_id)
        logger.debug(f"final_pod -----------------------\n{final_pod.display()}")

        ###
        ### SECRETS
        ###
        # Need to replace all "<<TAPIS_vars>>" with vals from secrets for example needs to work for "dsadsadsa <<TAPIS_mysecret>> dsadsadsa".
        # currently just the passwords db table. Eventually that'll become pods_env which itself could reference sk if that's needed.
        pods_env = Password.db_get_with_pk(pod.pod_id, pod.tenant_id, pod.site_id)
        pods_env = pods_env.dict()
        if final_pod.environment_variables:
            for key, val in final_pod.environment_variables.items():
                if isinstance(val, str):
                    # regex to create list of [<<TAPIS_*>> strings, str of inner variable without >><<]
                    matches = re.findall(r'<<TAPIS_(.*?)>>', val)
                    for match in matches:
                        final_pod.environment_variables[key] = val.replace(f"<<TAPIS_{match}>>", pods_env.get(match))
        #command
        if final_pod.command:
            for key in final_pod.command:
                if isinstance(key, str):
                    matches = re.findall(r'<<TAPIS_(.*?)>>', key)
                    for match in matches:
                        final_pod.command[key] = key.replace(f"<<TAPIS_{match}>>", pods_env.get(match))
        #arguments
        if final_pod.arguments:
            for key in final_pod.arguments:
                if isinstance(key, str):
                    matches = re.findall(r'<<TAPIS_(.*?)>>', key)
                    for match in matches:
                        final_pod.arguments[key] = key.replace(f"<<TAPIS_{match}>>", pods_env.get(match))

    volumes = []
    volume_mounts = []

    nfs_nfs_ip = get_nfs_ip()

    # Create PVC if requested.
    if pod.volume_mounts:
        for vol_name, vol_info in pod.volume_mounts.items():
            vol_info = vol_info.dict() # turn Resource back into dict.
            full_k8_name = f"{pod.k8_name}--{vol_name}"
            match vol_info.get("type"):
                case "tapisvolume":
                    nfs_volume = client.V1NFSVolumeSource(path = f"/", server = nfs_nfs_ip) # f"/podsnfs/{pod.tenant_id}/volumes/{vol_name}"
                    volumes.append(client.V1Volume(name = full_k8_name, nfs = nfs_volume))
                    volume_mounts.append(client.V1VolumeMount(name = full_k8_name, mount_path = vol_info.get("mount_path"), sub_path = f"{pod.tenant_id}/volumes/{vol_name}")) # vol_info.get("sub_path")))
                case "tapissnapshot":
                    nfs_volume = client.V1NFSVolumeSource(path = f"/", server = nfs_nfs_ip) # f"/podsnfs/{pod.tenant_id}/snapshots/{vol_name}"
                    volumes.append(client.V1Volume(name = full_k8_name, nfs = nfs_volume))
                    volume_mounts.append(client.V1VolumeMount(name = full_k8_name, mount_path = vol_info.get("mount_path"), sub_path = f"{pod.tenant_id}/snapshots/{vol_name}")) # vol_info.get("sub_path")))
                case "pvc":
                    create_pvc(name = full_k8_name)
                    persistent_volume = client.V1PersistentVolumeClaimVolumeSource(claim_name = full_k8_name)
                    volumes.append(client.V1Volume(name = full_k8_name, persistent_volume_claim = persistent_volume))
                    volume_mounts.append(client.V1VolumeMount(name = full_k8_name, mount_path = vol_info.get("mount_path"), sub_path = f"{pod.tenant_id}/volumes/{vol_name}"))
                case _:
                    pass
                    #error!

    # Each pod can have up to 3 networking objects with custom filled port/protocol/name
    # net_dict takes net_name:port.
    ports_dict = {}
    for net_name, net_info in pod.networking.items():
        if not isinstance(net_info, dict):
            net_info = net_info.dict()

        ports_dict.update({net_name: net_info['port']})

    container = {
        "name": pod.k8_name,
        "command": pod.command,
        "args": pod.arguments,
        "revision": revision,
        "image": pod.image,
        "ports_dict": ports_dict,
        "environment": pod.environment_variables.copy(),
        "mounts": [volumes, volume_mounts],
        "queue": pod.compute_queue,
        "mem_request": pod.resources.mem_request,
        "cpu_request": pod.resources.cpu_request,
        "mem_limit": pod.resources.mem_limit,
        "cpu_limit": pod.resources.cpu_limit,
        "gpus": pod.resources.gpus,
        "user": None
    }

    # Create init_container, container, and service.
    create_pod(**container)
    create_service(name = pod.k8_name, ports_dict = ports_dict)

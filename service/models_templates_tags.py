from asyncio import protocols
import http
import re
from sre_constants import ANY
from string import ascii_letters, digits
from secrets import choice
from datetime import datetime
from typing import List, Dict, Literal, Any, Set
from wsgiref import validate
from pydantic import BaseModel, Field, validator, root_validator, conint, create_model
from codes import PermissionLevel

from stores import pg_store
from tapisservice.tapisfastapi.utils import g
from tapisservice.config import conf
from tapisservice.logs import get_logger
logger = get_logger(__name__)

from __init__ import t

from sqlalchemy import UniqueConstraint
from sqlalchemy.inspection import inspect
from sqlalchemy.dialects.postgresql import ARRAY
from sqlmodel import Field, Session, SQLModel, select, JSON, Column, String
from models_base import TapisApiModel, TapisModel
from models_templates import Template
from models_misc import PermissionsModel, CredentialsModel, LogsModel
from models_images import Image
from typing import Optional


def derive_template_info(input_template_name, tenant: str = g.request_tenant_id, site: str = g.site_id):
    # template is in the format template_id:template_tag@2024-06-10-17:20:27
    # template_id is required, template_tag and timestamp are optional
    # If no template_tag, default to latest
    # If no timestamp, derive and use latest timestamp
    template_id = None
    template_tag = None
    tag_timestamp = None
    derived_template_tag = None
    if "@" in input_template_name:
        # we expect template_id:template_tag if @ is present
        template_id_n_tag, tag_timestamp = input_template_name.split("@")
        if ":" in template_id_n_tag:
            template_id, template_tag = template_id_n_tag.split(":")
        else:
            raise ValueError(f"Error finding template. User specified '@' with no ':'. Template should be formated as 'template_name:template_tag@tag_timestamp'.")
    elif ":" in input_template_name:
        # If no @, we expect template_id:template_tag if : is present
        template_id, template_tag = input_template_name.split(":")
    else:
        template_id = input_template_name

    logger.debug(f"Top of derive_template_info for template: {input_template_name}, tenant: {tenant}, site: {site}")
    ## template_id check
    template = Template.db_get_with_pk(template_id, tenant=tenant, site=site)
    if not template:
        raise ValueError(f"Error finding template. Could not find template with template_id: {template_id}.")
    if not template_tag:
        # If no template_tag, we'll use the latest tag.
        template_tag = "latest"

    ## template_tag check
    if template_tag and tag_timestamp:
        full_tag = f"{template_tag}@{tag_timestamp}"
        template_tags = TemplateTag.db_get_where(where_params=[['tag_timestamp', '.eq', full_tag]], sort_column='creation_ts', tenant=tenant, site=site)
        if not template_tags:
            raise ValueError(f"Error finding template tag. Could not find tag_timestamp matching: {input_template_name}. tenant: {tenant}, site: {site}.")
        if len(template_tags) > 1:
            raise ValueError(f"Error finding template tag. Found multiple tags when expecting only one: {input_template_name}. Big error. Message someone.")
        derived_template_tag = template_tags[0]
    elif not tag_timestamp:
        # timestamp not provided, we'll look for matching tags and set tag_timestamp to the most recent.
        template_tags = TemplateTag.db_get_where(where_params=[['tag', '.eq', template_tag]], sort_column='creation_ts', tenant=tenant, site=site)
        if not template_tags:
            raise ValueError(f"Could not find template matching: {template_id}:{template_tag}.")
        # found matching tags, get the most recent one.
        derived_template_tag = template_tags[0]
        _, tag_timestamp = derived_template_tag.tag_timestamp.split("@")

    logger.debug(f"End of derive_template_info for template: {input_template_name}, tenant: {tenant}, site: {site}")
    return f"{template_id}:{template_tag}@{tag_timestamp}", template, derived_template_tag


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


class Networking(TapisModel):
    protocol: str =  Field("http", description = "Which network protocol to use. `http`, `tcp`, `postgres`, or `local_only`. `local_only` is only accessible from within the cluster.")
    port: int = Field(5000, description = "Pod port to expose via networking.url in this networking object.")
    url: str = Field("", description = "URL used to access the port of the pod defined in this networking object. Generated by service.")
    ip_allow_list: list[str] = Field([], description = "List of IPs that are allowed to access this specific pod port. If empty, all IPs are allowed. ex. ['127.0.0.1/32', '192.168.1.7']")
    tapis_auth: bool = Field(False, description = "If true, will require Tapis auth to access the pod.")
    tapis_auth_response_headers: Dict[str, str] = Field({}, description = "Specification of headers to forward to the pod when using Tapis auth.")
    tapis_auth_allowed_users: list[str] = Field(["*"], description = "List of users allowed to access the pod when using Tapis auth.")
    tapis_auth_return_path: str = Field("/", description = "Path to redirect to when accessing the pod via Tapis auth.")
    tapis_ui_uri: str = Field("", description = "Path to redirect to when accessing the pod via Tapis UI.")
    tapis_ui_uri_redirect: bool = Field(False, description = "If true, will redirect to the tapis_ui_uri when accessing the pod via Tapis UI. Otherwise, just read-only uri.")
    tapis_ui_uri_description: str = Field("", description = "Describing where the tapis_ui_uri will redirect to.")

    @validator('protocol')
    def check_protocol(cls, v):
        v = v.lower()
        valid_protocols = ['http', 'tcp', 'postgres', 'local_only']
        if v not in valid_protocols:
            raise ValueError(f"networking.protocol must be one of the following: {valid_protocols}.")
        return v

    @validator('port')
    def check_port(cls, v):
        if 10 > v  or v > 99999:
            raise ValueError(f"networking.port must be an int with 2 to 5 digits. Got port: {v}")
        return v

    @validator('url')
    def check_url(cls, v):
        if v:
            # Regex match to ensure url is safe with only [A-z0-9.-] chars.
            res = re.fullmatch(r'[a-z][a-z0-9.-]+', v)
            if not res:
                raise ValueError(f"networking.url can only contain lowercase alphanumeric characters, periods, and hyphens.")
            # pod_id char limit = 64
            if len(v) > 128:
                raise ValueError(f"networking.url length must be below 128 characters. Inputted length: {len(v)}")
        return v

    @validator('tapis_auth_allowed_users')
    def check_tapis_auth_allowed_users(cls, v):
        if v:
            if not isinstance(v, list):
                raise TypeError(f"tapis_auth_allowed_users must be list. Got '{type(v).__name__}'.")
            for user in v:
                if not isinstance(user, str):
                    raise TypeError(f"tapis_auth_allowed_users must be list of str. Got '{type(user).__name__}'.")
        return v

    @validator('tapis_ui_uri')
    def check_tapis_ui_uri(cls, v):
        if v:
            # Regex match to ensure url is safe with only [A-z0-9.-/] chars.
            res = re.fullmatch(r'[a-z][a-z0-9.-/]+', v)
            if not res:
                raise ValueError(f"networking.tapis_ui_uri can only contain lowercase alphanumeric characters, periods, forward-slash, and hyphens.")
            # pod_id char limit = 64
            if len(v) > 128:
                raise ValueError(f"networking.tapis_ui_uri length must be below 128 characters. Inputted length: {len(v)}")
        return v
    
    @validator('tapis_ui_uri_description')
    def check_tapis_ui_uri_description(cls, v):
        # ensure tapis_ui_uri_description is all ascii
        if not v.isascii():
            raise ValueError(f"tapis_ui_uri_description field may only contain ASCII characters.")
        # make sure tapis_ui_uri_description < 255 characters
        if len(v) > 255:
            raise ValueError(f"tapis_ui_uri_description field must be less than 255 characters. Inputted length: {len(v)}")
        return v

    @root_validator(pre=False)
    def check_tapis_auth_fields(cls, values):
        protocol = values.get('protocol')
        tapis_auth = values.get('tapis_auth')

        if tapis_auth and protocol != "http":
            raise ValueError(f"tapis_auth can only be used with protocol 'http'.")

        return values



class Resources(TapisModel):
    # CPU/Mem defaults are set in configschema.json
    # CPU
    cpu_request: int = Field(None, description = "CPU allocation pod requests at startup. In millicpus (m). 1000 = 1 cpu.")
    cpu_limit: int = Field(None, description = "CPU allocation pod is allowed to use. In millicpus (m). 1000 = 1 cpu.")
    # Mem
    mem_request: int = Field(None, description = "Memory allocation pod requests at startup. In megabytes (Mi)")
    mem_limit: int = Field(None, description = "Memory allocation pod is allowed to use. In megabytes (Mi)")
    # GPU
    gpus: int = Field(None, description = "GPU allocation pod is allowed to use. In integers of GPUs. (we only have 1 currently ;) )")

    @validator('cpu_request', 'cpu_limit')
    def check_cpu_resources(cls, v):
        if not v:
            return v
        if conf.minimum_pod_cpu_val > v  or v > conf.maximum_pod_cpu_val:
            raise ValueError(
                f"resources.cpu_x out of bounds. Received: {v}. Maximum: {conf.maximum_pod_cpu_val}. Minimum: {conf.minimum_pod_cpu_val}.",
                 " User requires extra role to break bounds. Contact admin."
                )
        return v

    @validator('mem_request', 'mem_limit')
    def check_mem_resources(cls, v):
        if not v:
            return v
        if conf.minimum_pod_mem_val > v  or v > conf.maximum_pod_mem_val:
            raise ValueError(
                f"resources.mem_x out of bounds. Received: {v}. Maximum: {conf.maximum_pod_mem_val}. Minimum: {conf.minimum_pod_mem_val}.",
                 " User requires extra role to break bounds. Contact admin."
                )
        return v

    @validator('gpus')
    def check_gpus(cls, v):
        if not v:
            return v
        if 0 > v  or v > conf.maximum_pod_gpu_val:
            raise ValueError(
                f"resources.gpus out of bounds. Received: {v}. Maximum: {conf.maximum_pod_gpu_val}. Minimum: 0.",
                 " User requires extra role to break bounds. Contact admin."
                )
        return v
    @root_validator(pre=False)
    def ensure_request_lessthan_limit(cls, values):
        cpu_request = values.get("cpu_request")
        cpu_limit = values.get("cpu_limit")
        mem_request = values.get("mem_request")
        mem_limit = values.get("mem_limit")
        gpus = values.get("gpus") # There's no request/limit for gpus, just an int validated in check_gpus
        
        # Check cpu values
        if cpu_request and cpu_limit and cpu_request > cpu_limit:
            raise ValueError(f"resources.cpu_x found cpu_request({cpu_request}) > cpu_limit({cpu_limit}). Request must be less than or equal to limit.")
        
        # Check mem values
        if mem_request and mem_limit and mem_request > mem_limit:
            raise ValueError(f"resources.mem_x found mem_request({mem_request}) > mem_limit({mem_limit}). Request must be less than or equal to limit.")
        
        return values


class VolumeMount(TapisModel):
    type: str =  Field("", description = "Type of volume to attach.")
    mount_path: str = Field("/tapis_volume_mount", description = "Path to mount volume to.")
    sub_path: str = Field("", description = "Path to mount volume to.")

    @validator('type')
    def check_type(cls, v):
        v = v.lower()
        valid_types = ['tapisvolume', 'tapissnapshot', 'pvc']
        if v not in valid_types:
            raise ValueError(f"volumemount.type must be one of the following: {valid_types}.")
        return v

    @validator('mount_path')
    def check_mount_path(cls, v):
        return v

    @validator('sub_path')
    def check_sub_path(cls, v):
        return v


class TemplateTagPodDefinition(TapisModel):
    # All fields are optional and default to None or empty objects for easier parsing of modified fields later
    # Optional
    image: str = Field(None, description = "Which docker image to use, must be on allowlist, check /pods/images for list.")
    template: str = Field(None, description = "Name of template to base this template off of.")
    description: str = Field(None, description = "Description of this pod.")
    command: List[str] | None = Field(None, description = 'Command to run in pod. ex. `["sleep", "5000"]` or `["/bin/bash", "-c", "(exec myscript.sh)"]`', sa_column=Column(ARRAY(String)))
    arguments: List[str] | None = Field(None, description = "Arguments for the Pod's command.", sa_column=Column(ARRAY(String)))
    environment_variables: Dict[str, Any] = Field({}, description = "Environment variables to inject into k8 pod; Only for custom pods.", sa_column=Column(JSON))
    volume_mounts: Dict[str, VolumeMount] = Field({}, description = "Key: Volume name. Value: List of strs specifying volume folders/files to mount in pod", sa_column=Column(JSON))
    time_to_stop_default: int | None = Field(None, description = "Default time (sec) for pod to run from instance start. -1 for unlimited. 12 hour default.")
    time_to_stop_instance: int | None = Field(None, description = "Time (sec) for pod to run from instance start. Reset each time instance is started. -1 for unlimited. None uses default.")
    networking: Dict[str, Networking] = Field({}, description = 'Networking information. `{"url_suffix": {"protocol": "http"  "tcp", "port": int}}`', sa_column=Column(JSON))
    resources: Resources = Field({}, description = 'Pod resource management `{"cpu_limit": 3000, "mem_limit": 3000, "cpu_request": 500, "mem_limit": 500, "gpus": 0}`', sa_column=Column(JSON))
    compute_queue: str = Field("default", description = "Queue to run pod in. `default` is the default queue.")

    @validator('template')
    def check_template(cls, v):
        if v:
            template_name_str, template, template_tag = derive_template_info(v, g.tenant_id, g.site_id)
            return template_name_str
        else:
            return v

    @validator('description')
    def check_description(cls, v):
        if not v:
            return v
        # ensure description is all ascii
        if not v.isascii():
            raise ValueError(f"description field may only contain ASCII characters.")            
        # make sure description < 255 characters
        if len(v) > 255:
            raise ValueError(f"description field must be less than 255 characters. Inputted length: {len(v)}")
        return v

    @validator('environment_variables')
    def check_environment_variables(cls, v):
        if v:
            if not isinstance(v, dict):
                raise TypeError(f"environment_variable must be dict. Got {type(v).__name__}.")
            for env_key, env_val in v.items():
                if not isinstance(env_key, str):
                    raise TypeError(f"environment_variable key must be str. Got {type(env_key).__name__}.")
                if not isinstance(env_val, str):
                    raise TypeError(f"environment_variable val must be str. Got {type(env_val).__name__}.")
        return v

    @validator('volume_mounts')
    def check_volume_mounts(cls, v):
        if v:
            if not isinstance(v, dict):
                raise TypeError(f"volume_mounts must be dict. Got {type(v).__name__}.")
            for vol_name, vol_mounts in v.items():
                if not isinstance(vol_name, str):
                    raise TypeError(f"volume_mounts key must be str. Got {type(vol_name).__name__}.")
                if not vol_mounts:
                    raise ValueError(f"volume_mounts val must exist")
                vol_name_regex = re.fullmatch(r'[a-z][a-z0-9]+', vol_name)
                if not vol_name_regex:
                    raise ValueError(f"volume_mounts key must be lowercase alphanumeric. First character must be alpha.")
                
                # if volume name is "templatee-defined" we ignore checks and will have users fill-in later.
                if vol_name == "templatee-defined":
                    if vol_mounts.type == "tapisvolume":
                        volume = Volume.db_get_with_pk(vol_name, tenant=g.request_tenant_id, site=g.site_id)
                        if not volume:
                            raise ValueError(f"volume_mounts key must be a valid volume_id when type == 'tapisvolume'. Could not find volume_id: {vol_name}.")
                    if vol_mounts.type == "tapissnapshot":
                        snapshot = Snapshot.db_get_with_pk(vol_name, tenant=g.request_tenant_id, site=g.site_id)
                        if not snapshot:
                            raise ValueError(f"volume_mounts key must be a valid snapshot_id when type == 'tapissnapshot'. Could not find snapshot_id: {vol_name}.")
        return v


    @validator('arguments')
    def check_arguments(cls, v):
        if v:
            if not isinstance(v, list):
                raise TypeError(f"arguments must be list. Got {type(v).__name__}.")
            for arg in v:
                if not isinstance(arg, str):
                    raise TypeError(f"arguments must be list of str. Got {type(arg).__name__}.")
        return v

    @validator('command')
    def check_command(cls, v):
        if v:
            if not isinstance(v, list):
                raise TypeError(f"command must be list. Got {type(v).__name__}.")
            for arg in v:
                if not isinstance(arg, str):
                    raise TypeError(f"command must be list of str. Got {type(arg).__name__}.")
        return v

    @validator('image')
    def check_image(cls, v):
        # Template tag doesn't require image.
        if not v:
            return v
        if v.count(":") > 1:
            raise ValueError("image cannot have more than one ':' in the string. Should be used to separate the tag from the image name.")
        # We create object to check against image, that doesn't use docker tags though.
        if ":" in v:
            image_name_only = v.split(":")[0]

        # We search the siteadmintable schema for the images that our tenant is allowed to use.
        all_images = Image.db_get_all(tenant="siteadmintable", site=g.site_id)
        custom_allow_list = []
        for image in all_images:
            if g.tenant_id in image.tenants or "*" in image.tenants:
                custom_allow_list.append(image.image)
        # Then we add images from the conf.image_allow_list
        custom_allow_list += conf.image_allow_list or []

        if v.split(':')[0] not in custom_allow_list:
            raise ValueError(f"Custom template_tag.image images must be in allowlist. List available images with /pods/images; alternatively, speak to admin")

        return v

    @validator('time_to_stop_default')
    def check_time_to_stop_default(cls, v):
        if not v:
            return v
        if v != -1 and v < 300:
            raise ValueError(f"Pod time_to_stop_default must be -1 or be greater than 300 seconds.")
        return v

    @validator('time_to_stop_instance')
    def check_time_to_stop_instance(cls, v):
        if v and v != -1 and v < 300:
            raise ValueError(f"Pod time_to_stop_instance must be -1 or be greater than 300 seconds.")
        return v

    @validator('networking')
    def check_networking(cls, v):
        if v:
            # Only allow 3 url:port pairs per pod. Trying to keep services minimal.
            # I have uses for 2 ports, not 3, but might as well keep it available.
            if len(v) > 4:
                raise ValueError(f"networking dictionary may only contain up to 4 stanzas")

            # Check keys in networking dict
            # Check key is str, and properly formatted, this should be suffix to urls. "default" means no suffix.
            for env_key, env_val in v.items():
                if not isinstance(env_key, str):
                    raise TypeError(f"networking key must be str. Got type {type(env_key).__name__}.")
                res = re.fullmatch(r'[a-z0-9]+', env_key)
                if not res:
                    raise ValueError(f"networking key must be lowercase alphanumeric. Default is 'default'.")
                if len(env_key) > 64 or len(env_key) < 3:
                    raise ValueError(f"networking key length must be between 3-64 characters. Inputted length: {len(env_key)}")
        return v

    @validator('compute_queue')
    def check_compute_queue(cls, v):
        if v:
            # Ensure compute queue alphanumeric.
            res = re.fullmatch(r'[a-z0-9]+', v)
            if not res:
                raise ValueError(f"compute_queue must be lowercase alphanumeric.")

            #### Not needed for template tag, only for pod creation
            ### Check if the queue exists in config, database later
            # deducted_queue = get_queue_by_name(conf.compute_queues, v)
            # if not deducted_queue:
            #     raise ValueError(f"compute_queue must be in compute_queues list in cluster configuration.")
        return v


def combine_pod_and_template_recursively(input_obj, template_name, seen_templates=None, tenant: str = None, site: str = None):
    """
    --- run with
    pod = Pod.db_get_with_pk(pk_id='testingfastapi', tenant='dev', site='tacc')
    d = combine_pod_and_template_recursively(pod, "template21:car@2024-06-11-18:09:39")
    d.description
    """
    logger.debug(f"Top of combine_pod_and_template_recursively for template: {template_name}, tenant: {tenant}, site: {site}")
    if seen_templates is None:
        seen_templates = set()

    if template_name:
        if template_name in seen_templates:
            raise ValueError(f"Infinite loop detected: template {template_name} is referenced more than once in template waterfal.")
        seen_templates.add(template_name)

        template_name_str, template, template_tag = derive_template_info(template_name, tenant=tenant, site=site)
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

            logger.debug(f"End of combine_pod_and_template_recursively for template: {template_name}, tenant: {tenant}, site: {site}")
            try:
                if input_obj.resources and not type(input_obj.resources) == dict:
                    input_obj.resources = input_obj.resources.dict()
            except Exception as e:
                logger.debug(f'this resources part: Got exception when attempting to combine pod and templates: {e}')
                pass

            try:
                if input_obj.networking and not type(input_obj.networking) == dict:
                    input_obj.networking = input_obj.networking.dict()
            except Exception as e:
                logger.debug(f'this networking part: Got exception when attempting to combine pod and templates: {e}')
                pass

        except Exception as e:
            logger.debug(f'Got exception when attempting to combine pod and templates: {e}')

    return input_obj


#### TemplateTag models
class TemplateTag(TapisModel, table=True, validate=True):
    # Required
    template_id: str = Field(..., description="template_id this tag is linked to")#, foreign_key="template.template_id")
    # User Input
    pod_definition: TemplateTagPodDefinition = Field({}, description = "Pod definition for this template.", sa_column=Column(JSON))
    commit_message: str = Field("", description = "Commit message for this template tag.")
    tag: str = Field("latest", description = "Tag for this template. Default is 'latest'.")
    # Provided
    tag_timestamp: str = Field("", description = "tag@timestamp for this template tag.", primary_key=True, nullable=False)
    added_by: str = Field("", description = "User who added this template tag.")
    creation_ts: datetime | None = Field(None, description = "Time (UTC) that this template tag was created.")
    
    @validator('pod_definition')
    def check_pod_definition(cls, v):
        return v

    @validator('template_id')
    def check_template_id(cls, v):
        # existence check - can be done by foreign key, but it doesn't resolve template.template_id
        template = Template.db_get_with_pk(v, tenant=g.request_tenant_id, site=g.site_id)
        if not template:
            raise ValueError(f"template_id must exist in the database.")
        return v

    @validator('commit_message')
    def check_commit_message(cls, v):
        # ensure commit_message is all ascii
        if not v.isascii():
            raise ValueError(f"commit_message field may only contain ASCII characters.")            
        # make sure commit_message < 255 characters
        if len(v) > 255:
            raise ValueError(f"commit_message field must be less than 255 characters. Inputted length: {len(v)}")
        return v
    
    @validator('tag')
    def check_tag(cls, v):
        # ensure description is lowercase alphanumeric and hyphen
        if not re.match("^[a-zA-Z0-9-.]+$", v):
            raise ValueError(f"tag field may only contain lowercase alphanumeric characters and hyphens.")
        # make sure description < 80 characters
        if len(v) > 80:
            raise ValueError(f"tag field must be less than 80 characters. Inputted length: {len(v)}")
        return v

    @validator('added_by')
    def check_added_by(cls, v):
        if v:
            return v
        return g.username

    @validator('creation_ts')
    def check_creation_ts(cls, v):
        if v:
            return v
        return datetime.utcnow()
    
    @root_validator(pre=False)
    def set_tag_timestamp(cls, values):
        creation_ts = values.get('creation_ts')
        tag = values.get('tag')
        if not creation_ts:
            # must wait for creation_ts to be set before we can set tag_timestamp
            return values

        values['tag_timestamp'] = f"{tag}@{creation_ts.strftime('%Y-%m-%d-%H:%M:%S')}"
        return values

    def display(self):
        display = self.dict()
        return display
    
    def display_small(self):
        display = self.dict()
        display.pop('pod_definition')
        display.pop('template_id')
        return display


class TemplateTagNoDefinition(TapisApiModel):
    creation_ts: datetime | None = Field(None, description = "Time (UTC) that this template tag was created.")
    added_by: str = Field("", description = "User who added this template tag.")
    commit_message: str = Field("", description = "Commit message for this template tag.")
    tag: str = Field("latest", description = "Tag for this template. Default is 'latest'.")
    tag_timestamp: str = Field("", description = "tag@timestamp for this template tag.")


class NewTemplateTag(TapisApiModel):
    """
    Object with fields that users are allowed to specify for the Template class.
    """
    pod_definition: TemplateTagPodDefinition = Field(..., description = "Pod definition for this template tag.", sa_column=Column(JSON))
    commit_message: str = Field(..., description = "Commit message for this template tag.")
    tag: str = Field("latest", description = "Tag for this template. Default is 'latest'.")


class TemplateTagResponse(TapisApiModel):
    message: str
    metadata: Dict
    result: TemplateTag
    status: str
    version: str


class TemplateTagsResponse(TapisApiModel):
    message: str
    metadata: Dict
    result: List[TemplateTag]
    status: str
    version: str

class TemplateTagsSmallResponse(TapisApiModel):
    message: str
    metadata: Dict
    result: List[TemplateTagNoDefinition]
    status: str
    version: str

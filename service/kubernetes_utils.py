from fcntl import DN_DELETE
import json
import os
import time
import timeit
import datetime
import random
import re
from typing import Literal, Dict, List

from jinja2 import Environment, FileSystemLoader
from kubernetes import client, config, stream
from requests.exceptions import ReadTimeout, ConnectionError

from tapisservice.logs import get_logger
logger = get_logger(__name__)

from tapisservice.config import conf
from codes import AVAILABLE, CREATING
from stores import SITE_TENANT_DICT
from stores import pg_store
from sqlmodel import select

# k8 client creation
config.load_incluster_config()
k8 = client.CoreV1Api()

host_id = os.environ.get('SPAWNER_HOST_ID', conf.spawner_host_id)
logger.debug(f"host_id: {host_id};")

class KubernetesError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message

class KubernetesStartContainerError(KubernetesError):
    pass

class KubernetesStopContainerError(KubernetesError):
    pass


def get_kubernetes_namespaces():
    """
    Attempt to get namespace from filesystem
    Should be in file /var/run/secrets/kubernetes.io/serviceaccount/namespace
    
    We first take config, if not available, we grab from filesystem. Meaning
    config should usually be empty.
    """
    namespace = conf.get("kubernetes_worker_namespace", None)
    home_namespace = conf.get("kubernetes_namespace", None)

    if not namespace and not home_namespace:
        try:
            logger.debug("Attempting to get kubernetes_namespace from file.")
            with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace") as f:
                content = f.readlines()
                namespace = content[0].strip()
                home_namespace = namespace
        except Exception as e:
            logger.debug(f"Couldn't grab kubernetes namespace from filesystem. e: {e}")
        
    if not namespace:
        msg = "In get_kubernetes_namespaces(). Failed to get namespace."
        logger.debug(msg)
        raise KubernetesError(msg)
    logger.debug(f"In get_kubernetes_namespaces(). Got namespace: {namespace}.")
    return namespace, home_namespace

# Get k8 namespace for future use.
NAMESPACE, HOME_NAMESPACE = get_kubernetes_namespaces()

def rm_container(k8_name):
    """
    Remove a container. Async
    :param cid:
    :return:
    """    
    try:
        k8.delete_namespaced_pod(name=k8_name, namespace=NAMESPACE)
    except Exception as e:
        logger.info(f"Got exception trying to remove pod: {k8_name}. Exception: {e}")
        raise KubernetesError(f"Error removing pod {k8_name}, exception: {str(e)}")
    logger.info(f"delete_namespaced_pod ran for pod {k8_name}.")

def rm_service(service_name):
    """
    Remove a container. Async
    :param service_name:
    :return:
    """    
    try:
        k8.delete_namespaced_service(name=service_name, namespace=NAMESPACE)
    except Exception as e:
        logger.info(f"Got exception trying to remove service: {service_name}. Exception: {e}")
        raise KubernetesError(f"Error removing service {service_name}, exception: {str(e)}")
    logger.info(f"delete_namespaced_service ran for service {service_name}.")

def rm_pvc(pvc_name):
    """
    Remove a container. Async
    :param service_id:
    :return:
    """    
    try:
        k8.delete_namespaced_persistent_volume_claim(name=pvc_name, namespace=NAMESPACE)
    except Exception as e:
        logger.info(f"Got exception trying to remove pvc: {pvc_name}. Exception: {e}")
        raise KubernetesError(f"Error removing pvc {pvc_name}, exception: {str(e)}")
    logger.info(f"delete_namespaced_persistent_volume_claim ran for pvc {pvc_name}.")

def list_all_containers(filter_str: str = "pods"):
    """Returns a list of all containers in a particular namespace """
    pods = k8.list_namespaced_pod(NAMESPACE).items
    # filter pods by filter_str
    pods = [pod for pod in pods if filter_str in pod.metadata.name]
    return pods

def list_all_services(filter_str: str = "pods"):
    """Returns a list of all containers in a particular namespace """
    services = k8.list_namespaced_service(NAMESPACE).items
    # filter services by filter_str
    services = [service for service in services if filter_str in service.metadata.name]
    return services

def get_current_k8_pods(service_name: str = "pods", site_id: str = conf.site_id):
    """
    The get_current_k8_pods function returns a list of dictionaries containing the following keys:
        - pod_info: The Kubernetes API object for the container.
        - site_id: The site ID (e.g., 'east', 'west') where this container is located.
        - tenant_id: The tenant ID (e.g., 'acme-prod') where this container is located.
        - pod_id: A string representing the name of the pod, e.g., &quot;pods-east-acme-prod&quot;.  This value can be used to filter out pods in other sites or tenants when needed.
    
    :param filter_str:str=&quot;pods&quot;: Filter the list of containers
    :return: A list of dictionaries
    :doc-author: Trelent
    """
    """Get all containers, filter for just db, and display."""
    filter_str = f"{service_name}-{site_id}"
    db_containers = []
    for k8_pod in list_all_containers(filter_str=filter_str):
        k8_name = k8_pod.metadata.name
        # db name format = "pods-<site>-<tenant>-<pod_id>
        # so split on - to get parts (containers use _, pods use -)
        try:
            parts = k8_name.split('-')
            site_id = parts[1]
            tenant_id = parts[2]
            pod_id = parts[3]
            db_containers.append({'pod_info': k8_pod,
                                    'site_id': site_id,
                                    'tenant_id': tenant_id,
                                    'pod_id': pod_id,
                                    'k8_name': k8_name})
        except Exception as e:
            msg = f"Exception parsing k8 pods. e: {e}"
            print(msg)
            pass
    return db_containers

def get_current_k8_services(service_name: str = "pods", site_id: str = conf.site_id):
    """
    The get_current_k8_service function returns a list of dictionaries containing the following keys:
        - service_info: The Kubernetes API object for the container.
        - site_id: The site ID (e.g., 'east', 'west') where this container is located.
        - tenant_id: The tenant ID (e.g., 'acme-prod') where this container is located.
        - pod_id: A string representing the name of the pod, e.g., &quot;pods-east-acme-prod&quot;.  This value can be used to filter out pods in other sites or tenants when needed.
    
    :param filter_str:str=&quot;pods&quot;: Filter the list of containers
    :return: A list of dictionaries
    :doc-author: Trelent
    """
    """Get all containers, filter for just db, and display."""
    filter_str = f"{service_name}-{site_id}"
    db_services = []
    for k8_service in list_all_containers(filter_str=filter_str):
        k8_name = k8_service.metadata.name
        # db name format = "pods-<site>-<tenant>-<pod_id>
        # so split on - to get parts (containers use _, pods use -)
        try:
            parts = k8_name.split('-')
            site_id = parts[1]
            tenant_id = parts[2]
            pod_id = parts[3]
            db_services.append({'service_info': k8_service,
                                'site_id': site_id,
                                'tenant_id': tenant_id,
                                'pod_id': pod_id,
                                'k8_name': k8_name})
        except Exception as e:
            msg = f"Exception parsing k8 services. e: {e}"
            print(msg)
            pass
    return db_services

def get_k8_logs(name: str):
    try:
        logs = k8.read_namespaced_pod_log(namespace=NAMESPACE, name=name)
        return logs
    except Exception as e:
        return ""

def run_k8_exec(k8_name: str, command: list, namespace: str = ""):
    # This starts a Kubernetes exec in the background. We can poll progress/status
    # if the exec is still running with resp.is_open().
    ### EXAMPLE
    #    command = ["/bin/sh", "-c", "awk -v ORS='\\n' '1' /home/pods/.ssh/podskey"]
    #    derived_private_key, derived_err = run_k8_exec(k8_name, command)
    resp = stream.stream(
        k8.connect_get_namespaced_pod_exec,
        k8_name,
        namespace or NAMESPACE,
        command=command,
        stderr=True, stdin=False,
        stdout=True, tty=False,
        _preload_content=False)
    
    # Alternative. Checks on stderr and stdout while exec is still running. 
    # while resp.is_open()
    #     resp.update(timeout=1)
    #     if resp.peek_stdout():
    #         print(f"{resp.read_stdout()}")
    #     if resp.peek_stderr():
    #         print(f"STDERR: \n\n{resp.read_stderr()}\n")

    # Waits till exec is complete and then grab results
    while resp.is_open():
        resp.update(timeout=1)

    # get stdout and stderr
    stdout = resp.read_stdout()
    stderr = resp.read_stderr()
    
    return stdout, stderr

def container_running(name: str):
    """
    Check if k8 pod is currently running.

    Args:
        name (str): Name of k8 pod to look for, pods-<site>-<tenant>-<pod_id> format.
    
    Raises:
        KeyError: _description_
        KubernetesError: K8 got an error running read_namespaced_pod().

    Returns:
        bool: True if running, False otherwise.
    """
    logger.debug("top of kubernetes_utils.container_running().")
    if not name:
        raise KeyError(f"kubernetes_utils.container_running received name: {name}")
    try:
        if k8.read_namespaced_pod(namespace=NAMESPACE, name=name).status.phase == 'Running':
            return True
    except client.ApiException:
        # pod not found
        return False
    except Exception as e:
        msg = f"There was an error checking kubernetes_utils.container_running for name: {name}. Exception: {e}"
        logger.error(msg)
        raise KubernetesError(msg)
    
def stop_container(name: str):
    """
    Attempt to stop running pod, with retry logic. Should only be called with a running pod.

    Args:
        name (str): Name of k8 pod to stop, pods-<site>-<tenant>-<pod_id> format.

    Raises:
        KeyError: _description_
        KubernetesStopContainerError: _description_

    Returns:
        bool: True if pod deleted successfully, False otherwise.
    """
    if not name:
        raise KeyError(f"kubernetes_utils.container_running received name: {name}")

    i = 0
    while i < 10:        
        try:
            k8.delete_namespaced_pod(namespace=NAMESPACE, name=name)
            return True
        except client.ApiException:
            # pod not found
            return False
        except Exception as e:
            logger.error(f"Got another exception trying to stop the actor container. Exception: {e}")
            i += 1
            continue
    raise KubernetesStopContainerError("Error. Pod not deleted after 10 attempts.")

def deduct_queue_settings(
    requested_queue_name: str = "",
    gpus_requested: int = 0,
    mem_request: str | None = None,
    cpu_request: str | None = None,
    mem_limit: str | None = None,
    cpu_limit: str | None = None):
    """
    Deducts K8 settings settings based on requested_queue_name and config.yml.
    
    Logic:
    - If queue name is requested:
        - sets tolerations
        - sets node selector
    If gpus are requested:
        - sets above + gpu resources
    If neither are requested:
        - use default queue (no settings essentially)
    
    Inputs:
        requested_queue_name (str, optional): if queue exists we'll use queue settings that exist.
        gpus_requested (int, optional): number of gpus requested. Defaults to 0.
    
    Returns:
        node_selector, tolerations, resources
    """
    def get_queue_by_name(cluster_queues, queue_name):
        for queue in cluster_queues:
            if queue['queue_name'] == queue_name:
                return queue
        return None

    logger.debug("top of kubernetes_utils.deduct_queue_settings().")

    ### Deduct queue!
    deducted_queue = get_queue_by_name(conf.cluster_queues, requested_queue_name)
    if not deducted_queue:
        logger.warning(f"Queue not found for requested_queue_name: {requested_queue_name}. Using default queue.")
        deducted_queue = get_queue_by_name(conf.cluster_queues, "default")

    ### Node Selector - in the form of "gpu,v100"
    # must transform to dict(str, str)
    node_selector_keyval = deducted_queue.get('node_selector', None)
    # validate that node selector string is comma seperated key val
    node_selector = None
    if node_selector_keyval:
        try:
            ns_key, ns_val = node_selector_keyval.split(',')
            # insure vars are lowercase alphanumeric or - only
            for v in [ns_key, ns_val]:      
                res = re.fullmatch(r'[a-z][a-z0-9-]+', v)
                if not res:
                    msg = f"Node selector should be lowercase alphanumeric. Key/Val: {ns_key}/{ns_val}"
                    logger.error(msg)
                    raise KubernetesStartContainerError(msg)
                if len(v) > 50:
                    raise ValueError(f"Node selector key/val too long. Limit 50. Key/Val: {ns_key}/{ns_val}")
            node_selector = {ns_key: ns_val}
        except Exception as e:
            msg = f"Node selector keyval not in correct format. e: {e}"
            logger.error(msg)
            raise KubernetesStartContainerError(msg)

    ### Tolerations
    tolerations = []
    for toleration in deducted_queue.get('tolerations', []):
        tolerations.append(client.V1Toleration(**toleration))

    ### Resources - CPU/MEM
    # Defining kubernetes requests/limits
    # Memory - k8 uses no suffix (for bytes), Ki, Mi, Gi, Ti, Pi, or Ei (Does not accept kb, mb, or gb at all)
    # CPUs - In millicpus (m)
    # Limits
    resource_limits = {}
    if mem_limit:
        resource_limits["memory"] = f"{mem_limit}Mi"
    if cpu_limit:
        resource_limits["cpu"] = f"{cpu_limit}m"
    # Requests
    resource_requests = {}
    if mem_request:
        resource_requests["memory"] = f"{mem_request}Mi"
    if cpu_request:
        resource_requests["cpu"] = f"{cpu_request}m"

    ### Resources - GPU part
    # if gpus are requested, look for queue gpu array
    # gpus_requested int must be satisfied by gpus available
    # for now all gpus should be the same, so we're just looking at total for queue
    # later, users might be able to specify specific gpus, at which point we'll need to check
    # if the requested gpus are available in the queue or if the queue has enough
    # Readme has good info - https://github.com/NVIDIA/k8s-device-plugin
    ### Time-sliced gpus - 1 gpu can be sliced into multiple time-sliced gpus
    # Selecting 2 could mean 2 of 10 slices of a gpu. Equivalent to 1 of 10 slices in terms of compute/implementation.
    # Meaning max request for a time-sliced gpu is 1.
    ### Full gpus - Requested gpus are full gpus. 2 means 2 full gpus.    
    # Probably need some more work for true multi-GPU specifications, but for now this is a good start.
    logger.debug(f"Requested gpus: {gpus_requested}")
    if gpus_requested:
        logger.debug(f"GPUs have been requested, amount: {gpus_requested}")
        gpu_resources = deducted_queue.get('gpu_resources', [])
        logger.debug(f"GPU resource config: {gpu_resources}")

        total_gpus = 0
        for gpu_resource in gpu_resources:
            # There's currently only one, this'll overwrite if there's more.
            activation_resource = gpu_resource.get('activation_resource', None)
            logger.debug(f"Found activation resource: {activation_resource}")
            if not activation_resource:
                msg = f"Queue: {requested_queue_name} does not have an activation resource."
                logger.error(msg)
                raise KubernetesStartContainerError(msg)
            # time-sliced gpus should only count as 1 even if multiple slices are available
            if "gpu.shared" in activation_resource:
                total_gpus += 1
            else:
                total_gpus += gpu_resource.get('max_gpu_request', 0)

        logger.debug(f"Total gpus available: {total_gpus}")

        if gpus_requested > total_gpus:
            msg = f"Requested gpus: {gpus_requested} is greater than total gpus available: {total_gpus}."
            logger.error(msg)
            raise KubernetesStartContainerError(msg)

        resource_limits[activation_resource] = gpus_requested
        resource_requests[activation_resource] = gpus_requested

    # Define resource requirements if resource limits specified
    resources = client.V1ResourceRequirements(limits = resource_limits, requests = resource_requests)
    logger.debug(f"queue: {deducted_queue.get('queue_name')}\n"
                 f"node_selector: {node_selector}\n"
                 f"tolerations: {tolerations}\n"
                 f"resource_requests: {resource_requests}\n"
                 f"resource_limits: {resource_limits}")

    return node_selector, tolerations, resources

def create_pod(name: str,
               image: str,
               revision: int,
               command: List | None = None,
               args: List | None = None,
               init_command: List | None = None,
               ports_dict: Dict = {},
               environment: Dict = {},
               mounts: List = [],
               mem_request: str | None = None,
               cpu_request: str | None = None,
               mem_limit: str | None = None,
               cpu_limit: str | None = None,
               queue: str | None = None,
               gpus: int = 0,
               user: str | None = None,
               image_pull_policy: Literal["Always", "IfNotPresent", "Never"] = "Always"):
    """
    Creates and runs a k8 pod.

    Notes:
    Not like Abaco. This is purely container creation using inputs. Nothing specific to the pod to be created.
    Meaning, no permissions, no adding conf files.

    Args:
        name (str): _description_
        image (str): _description_
        revision (int): _description_
        command (List): _description_
        ports_dict (Dict, optional): _description_. Defaults to {}.
        environment (Dict, optional): _description_. Defaults to {}.
        mounts (List, optional): _description_. Defaults to [].
        mem_limit (str | None, optional): _description_. Defaults to None.
        max_cpus (str | None, optional): _description_. Defaults to None.
        user (str | None, optional): _description_. Defaults to None.
        image_pull_policy ("Always" | "IfNotPresent" | "Never"): _description_. Defaults to "Always".

    Raises:
        KubernetesStartContainerError: _description_
        KubernetesError: _description_

    Returns:
        k8pod: Pod info resulting from create_namespaced_pod.
    """    
    logger.debug("top of kubernetes_utils.create_pod().")

    ### Ports
    ports = []
    for port_name, port_val in ports_dict.items():
        ports.append(client.V1ContainerPort(name=port_name, container_port=port_val))
    logger.debug(f"Pod declared ports: {ports}")

    ### Environment
    environment.update({
        'image': image,
        'revision': revision,
        # Kubernetes sets some default envs. We write over these here + use enable_service_links=False in PodSpec
        'KUBERNETES_PORT': "",
        'KUBERNETES_SERVICE_HOST': "",
        'KUBERNETES_SERVICE_PORT': "",
        'KUBERNETES_SERVICE_PORT_HTTPS': "",
        'KUBERNETES_PORT_443_TCP': "",
        'KUBERNETES_PORT_443_TCP_ADDR': "",
        'KUBERNETES_PORT_443_TCP_PORT': "",
        'KUBERNETES_PORT_443_TCP_PROTO': ""        
    })
    env = []
    for env_name, env_val in environment.items():
        env.append(client.V1EnvVar(name=env_name, value=str(env_val)))
    logger.debug(f"Pod declared environment variables: {env}")

    ### Volumes/Volume Mounts
    # Get mounts ready for k8 spec
    if mounts:
        volumes, volume_mounts = mounts
    else:
        volumes = []
        volume_mounts = []
    logger.debug(f"Volumes: {volumes}; pod_id: {name}")
    logger.debug(f"Volume_mounts: {volume_mounts}; pod_id: {name}")

    ### Resources - CPU/MEM/GPU settings based off of queue
    node_selector, tolerations, resources = deduct_queue_settings(queue, gpus, mem_request, cpu_request, mem_limit, cpu_limit)

    ## If GPU is requested.
    if gpus:
        #dns_config = client.V1PodDNSConfig(nameservers=['8.8.8.8']) # I don't believe this dns config is needed. But maybe?
        dns_config = None
    else:
        dns_config = None

    ### Security Context
    security_context = None
    uid = None
    gid = None
    if user:
        try:
            # user should be None or "223232:323232" ("uid:gid")
            uid, gid = user.split(":")
        except Exception as e:
            # error starting the pod, user will need to debug
            msg = f"Got exception getting user uid/gid: {e}; pod_id: {name}"
            logger.info(msg)
            raise KubernetesStartContainerError(msg)
    # Define security context if uid and gid are found
    if uid and gid:
        security = client.V1SecurityContext(run_as_user=uid, run_as_group=gid)

    ### Init container creation
    if init_command:
        init_container = client.V1Container(
            name=f"{name}-init",
            command=init_command,
            image=image,
            volume_mounts=volume_mounts,
            env=env,
            resources=resources,
            image_pull_policy=image_pull_policy
        )
        init_containers = [init_container]
    else:
        init_containers = []

    ### Define and start the pod
    try:
        container = client.V1Container(
            name=name,
            command=command,
            args=args,
            image=image,
            volume_mounts=volume_mounts,
            env=env,
            resources=resources,
            ports=ports,
            image_pull_policy=image_pull_policy
        )
        pod_spec = client.V1PodSpec(
            init_containers=init_containers,
            containers=[container],
            dns_config = dns_config,
            volumes=volumes,
            restart_policy="Never",
            security_context=security_context,
            enable_service_links=False,
            tolerations=tolerations,
            node_selector=node_selector
        )
        pod_metadata = client.V1ObjectMeta(
            name=name,
            labels={"app": name}
        )
        pod_body = client.V1Pod(
            metadata=pod_metadata,
            spec=pod_spec,
            kind="Pod",
            api_version="v1"
        )
        k8_pod = k8.create_namespaced_pod(
            namespace=NAMESPACE,
            body=pod_body
        )
    except Exception as e:
        msg = f"Got exception trying to create pod with image: {image}. {repr(e)}. e: {e}"
        logger.info(msg)
        raise KubernetesError(msg)
    logger.info(f"Pod created successfully.")
    return k8_pod


def create_service(name, ports_dict={}):
    """
    Takes a given dict of ports and creates a service for a specific k8 pod.

    Args:
        name (_type_): _description_
        ports_dict (dict, optional): _description_. Defaults to {}.

    Raises:
        KubernetesError: _description_

    Returns:
        _type_: _description_
    """
    logger.debug("top of kubernetes_utils.create_service().")

    ### Ports
    ports = []
    for port_name, port_val in ports_dict.items():
        ports.append(client.V1ServicePort(name=port_name, port=port_val, target_port=port_val))
    logger.debug(f"Pod declared ports: {ports}")

    ### Define and start the service
    try:
        service_spec = client.V1ServiceSpec(
            selector={"app": name},
            type="ClusterIP",
            ports=ports
        )
        service_body = client.V1Service(
            metadata=client.V1ObjectMeta(name=name),
            spec=service_spec,
            kind="Service",
            api_version="v1"
        )
        k8_service = k8.create_namespaced_service(
            namespace=NAMESPACE,
            body=service_body
        )
    except Exception as e:
        msg = f"Got exception trying to start service with name: {name}. {e}"
        logger.info(msg)
        raise KubernetesError(msg)
    logger.info(f"Pod service started successfully.")
    return k8_service


def create_pvc(name):
    logger.debug("top of kubernetes_utils.create_pvc().")

    ### Define and create the pvc
    try:
        pvc_resources = client.V1ResourceRequirements(
            requests={"storage": "10Gi"}
        )
        pvc_spec = client.V1PersistentVolumeClaimSpec(
            access_modes=["ReadWriteOnce"],
            storage_class_name=conf.pvc_storage_class_name,
            resources=pvc_resources
        )
        pvc_body = client.V1PersistentVolumeClaim(
            metadata=client.V1ObjectMeta(name=name),
            spec=pvc_spec,
            kind="PersistentVolumeClaim",
            api_version="v1"
        )
        k8_pvc = k8.create_namespaced_persistent_volume_claim(
            namespace=NAMESPACE,
            body=pvc_body
        )
    except Exception as e:
        msg = f"Got exception trying to start pvc with name: {name}. {e}"
        logger.info(msg)
        k8_pvc = True
        #raise KubernetesError(msg)
    logger.info(f"Pod pvc started successfully.")
    return k8_pvc


def update_traefik_configmap(tcp_proxy_info: Dict[str, Dict[str, str]],
                             http_proxy_info: Dict[str, Dict[str, str]],
                             postgres_proxy_info: Dict[str, Dict[str, str]]):
    """
    Update fn for proxy configmap. Will read kubernetes/db data and create proxy server stanza bits where neccessary.
    Should be site specific.

    Args:
        proxy_info ({"pod_id1": {"routing_port": int, "url": str, "k8_service": str}, ...}): Dict of dict that
            specifies routing port + url needed to create pod service.
    """
    logger.info("Top of update_traefik_configmap().")
    template_env = Environment(loader=FileSystemLoader("service/templates"))
    template = template_env.get_template('traefik-template.j2')
    rendered_template = template.render(tcp_proxy_info = tcp_proxy_info,
                                        http_proxy_info = http_proxy_info,
                                        postgres_proxy_info = postgres_proxy_info,
                                        namespace = NAMESPACE)

    # Only update the configmap if the current configmap is out of date.
    current_template = k8.read_namespaced_config_map(name='pods-traefik-conf', namespace=NAMESPACE)
    
    logger.info("Health checking for difference in Traefik configs.")
    if not current_template.data['traefik.yml'] == rendered_template:
        logger.debug("Health found difference in Traefik configs, updated configmap.")
        # Update the configmap with the new template immediately.
        config_map = client.V1ConfigMap(data = {"traefik.yml": rendered_template})
        k8.patch_namespaced_config_map(name='pods-traefik-conf', namespace=NAMESPACE, body=config_map)
        # Auto updates proxy pod. Changes take place according to kubelet sync frequency duration (60s default).

def get_traefik_configmap():
    """
    """
    current_template = k8.read_namespaced_config_map(name='pods-traefik-conf', namespace=NAMESPACE)
    
    return current_template

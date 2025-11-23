#!/usr/bin/env python3
"""
OCI MCP Server
- Tools for Compute / DB / Object Storage discovery and simple actions
- Resource providers (e.g., compartments)
- A prompt for summarizing findings

Transports: stdio (default)
"""

from __future__ import annotations

import os
import json
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# MCP (official Python SDK)
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

# OCI SDK
import oci
from oci.util import to_dict

# ---------- Logging & env ----------
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("oci-mcp")

# ---------- OCI helper ----------

class OCIManager:
    """Simple manager to create OCI clients using ~/.oci/config or env-based auth."""

    def __init__(self) -> None:
        self.config = self._load_config()
        self.signer = None  # for instance principals etc.

    def _load_config(self) -> Dict[str, Any]:
        # Prefer config file if present
        cfg_file = os.getenv("OCI_CONFIG_FILE", os.path.expanduser("~/.oci/config"))
        profile = os.getenv("OCI_CONFIG_PROFILE", "DEFAULT")
        if os.path.exists(cfg_file):
            log.info(f"Using OCI config file: {cfg_file} [{profile}]")
            return oci.config.from_file(cfg_file, profile_name=profile)

        # Else try explicit env vars
        env_keys = ("OCI_USER_OCID","OCI_FINGERPRINT","OCI_TENANCY_OCID","OCI_REGION","OCI_KEY_FILE")
        if all(os.getenv(k) for k in env_keys):
            cfg = {
                "user": os.environ["OCI_USER_OCID"],
                "fingerprint": os.environ["OCI_FINGERPRINT"],
                "tenancy": os.environ["OCI_TENANCY_OCID"],
                "region": os.environ["OCI_REGION"],
                "key_file": os.environ["OCI_KEY_FILE"],
            }
            log.info("Using explicit OCI env var configuration")
            return cfg

        # Finally, try instance principals (for servers running on OCI)
        try:
            self.signer = oci.auth.signers.get_resource_principals_signer()
            region = os.getenv("OCI_REGION", "ap-melbourne-1")
            cfg = {"region": region, "tenancy": os.getenv("OCI_TENANCY_OCID", "")}
            log.info("Using instance/resource principals signer")
            return cfg
        except Exception:
            raise RuntimeError(
                "No OCI credentials found. Run `oci setup config` or set env vars "
                "(OCI_USER_OCID, OCI_FINGERPRINT, OCI_TENANCY_OCID, OCI_REGION, OCI_KEY_FILE)."
            )

    def get_client(self, service: str):
        """Return an OCI service client bound to configured region/signer."""
        service = service.lower()
        kwargs = {}
        if self.signer:
            kwargs["signer"] = self.signer

        if service in ("identity", "iam"):
            return oci.identity.IdentityClient(self.config, **kwargs)
        if service in ("compute", "core"):
            return oci.core.ComputeClient(self.config, **kwargs)
        if service in ("network", "virtualnetwork", "vcn"):
            return oci.core.VirtualNetworkClient(self.config, **kwargs)
        if service in ("database", "db"):
            return oci.database.DatabaseClient(self.config, **kwargs)
        if service in ("object_storage", "objectstorage", "os"):
            return oci.object_storage.ObjectStorageClient(self.config, **kwargs)
        if service in ("usage", "usage_api", "cost"):
            try:
                return oci.usage_api.UsageapiClient(self.config, **kwargs)  # type: ignore[attr-defined]
            except Exception as e:
                raise RuntimeError("Usage API client not available; check OCI SDK version.") from e
        if service in ("resource_search", "search"):
            return oci.resource_search.ResourceSearchClient(self.config, **kwargs)
        if service in ("audit", "audit_service"):
            return oci.audit.AuditClient(self.config, **kwargs)
        if service in ("logging_search", "log_search", "logging"):
            return oci.loggingsearch.LogSearchClient(self.config, **kwargs)

        raise ValueError(f"Unknown OCI service: {service}")


oci_manager = OCIManager()

# Utility: default compartment
def _default_compartment() -> Optional[str]:
    return os.getenv("DEFAULT_COMPARTMENT_OCID") or oci_manager.config.get("tenancy")

# Utility: safe dict conversion for OCI models/collections
def _to_clean_dict(x: Any) -> Any:
    try:
        return to_dict(x)
    except Exception:
        return json.loads(json.dumps(x, default=str))


# ---------- MCP server ----------

MCP_TOKEN = os.getenv("MCP_TOKEN", "change_me_super_secret")
verifier = StaticTokenVerifier(
    tokens={MCP_TOKEN: {"client_id": "oci-mcp", "scopes": ["read"]}}
)

# mcp = FastMCP("oci-mcp-server", auth=verifier)
mcp = FastMCP("oci-mcp-server")


@mcp.tool()
def list_compute_instances(compartment_ocid: Optional[str] = None,
                           lifecycle_state: Optional[str] = None) -> List[Dict[str, Any]]:
    """List Compute instances.
    Args:
        compartment_ocid: Compartment OCID (defaults to tenancy if omitted)
        lifecycle_state: Optional filter (e.g., RUNNING, STOPPED)
    Returns:
        Array of instance summaries (OCID, display_name, shape, lifecycle_state, time_created)
    """
    comp = compartment_ocid or _default_compartment()
    assert comp, "No compartment OCID available"
    compute = oci_manager.get_client("compute")
    items = []
    for inst in oci.pagination.list_call_get_all_results(
        compute.list_instances, compartment_id=comp
    ).data:
        if lifecycle_state and inst.lifecycle_state != lifecycle_state:
            continue
        image = compute.get_image(inst.image_id).data
        items.append({
            "id": inst.id,
            "display_name": inst.display_name,
            "shape": inst.shape,
            "shape_config": (
                inst.shape_config.to_dict()
                if hasattr(inst.shape_config, "to_dict")
                else {
                    "burstable": getattr(inst.shape_config, "baseline_ocpu_utilization", None),
                    "ocpus": getattr(inst.shape_config, "ocpus", None),
                    "memory_in_gbs": getattr(inst.shape_config, "memory_in_gbs", None),
                    "vcpus": getattr(inst.shape_config, "vcpus", None),
                    "processor_description": getattr(inst.shape_config, "processor_description", None),
                    "gpus": getattr(inst.shape_config, "gpus", None),
                    "gpu_description": getattr(inst.shape_config, "gpu_description", None),
                }),
            "image": image.display_name,
            "operating_system": image.operating_system,
            "operating_system_version": image.operating_system_version,
            "lifecycle_state": inst.lifecycle_state,
            "time_created": inst.time_created.isoformat() if inst.time_created else None,
            "compartment_id": inst.compartment_id,
            "availability_domain": getattr(inst, "availability_domain", None),
        })
    return items

@mcp.tool()
def search_oci_resources(resource_type: Optional[str] = None,
                         compartment_ocid: Optional[str] = None) -> List[Dict[str, Any]]:
    """Search/Find any OCI resources by just specifying the resource type.
    Can search for ALL resources or filter by specific resource type and/or compartment. If you are looking for any type of resource,
    then just do not specify the resource_type. The default is to search for all resources. Only specify the resource_type if the user
    asked for a specific type of resource.

    Args:
        resource_type: The resource type to query for (optional). If not specified, uses "all" to find ALL resources.
                       The name after the colon is the resource type. See list below.
        compartment_ocid: Optional Compartment OCID to filter resources by compartment.
                          When provided, only resources in the specified compartment will be returned.
    
    Note: Use resource_type="all" (or omit resource_type) to find ALL resources across all types.
    
    Supported resource types (the name after the colon is the resource_type value):
        - Application Performance Monitoring: apmdomain
        - Analytics Cloud: analyticsinstance
        - API Gateway: apideployment
        - API Gateway: apigateway
        - API Gateway: apigatewayapi
        - API Gateway: apigatewaycertificate
        - Application Dependency Management: admknowledgebase
        - Application Dependency Management: admvulnerabilityaudit
        - Autonomous Recovery Service: ProtectedDatabase
        - Autonomous Recovery Service: ProtectionPolicy
        - Autonomous Recovery Service: RecoveryServiceSubnet
        - Bastion: bastion
        - Big Data Service: bigdataservice
        - Big Data Service: bigdataserviceapikey
        - Big Data Service: bigdataservicemetastoreconfig
        - Big Data Service: bigdataservicelakehouseconfig
        - Block Volume: bootvolume
        - Block Volume: bootvolumebackup
        - Block Volume: bootvolumereplica
        - Block Volume: volume
        - Block Volume: volumebackup
        - Block Volume: volumebackuppolicy
        - Block Volume: volumegroup
        - Block Volume: volumegroupbackup
        - Block Volume: volumereplica
        - Blockchain Platform: blockchainplatforms
        - Budgets: budget
        - Certificates: cabundle
        - Certificates: cabundleassociation
        - Certificates: certificate
        - Certificates: certificateassociation
        - Certificates: certificateauthority
        - Certificates: certificateauthorityassociation
        - Cloud Guard: cloudguarddetectorrecipe
        - Cloud Guard: cloudguardmanagedlist
        - Cloud Guard: cloudguardresponderrecipe
        - Cloud Guard: cloudguardtarget
        - Cluster Placement Groups: clusterplacementgroup
        - Compute: autoscalingconfiguration
        - Compute: clusternetwork
        - Compute: computecapacityreservation
        - Compute: consolehistory
        - Compute: dedicatedvmhost
        - Compute: image
        - Compute: instance
        - Compute: instanceconfiguration
        - Compute: instancepool
        - Compute Cloud@Customer: ccc-infrastructure
        - Compute Cloud@Customer: ccc-upgrade-schedule
        - Connector Hub: serviceconnector
        - Container Instances: container
        - Container Instances: containerinstance
        - Content Management: oceinstance
        - Console Dashboards: ConsoleDashboard
        - Console Dashboards: ConsoleDashboardGroup
        - Data Catalog: datacatalog
        - Data Catalog: datacatalogprivateendpoint
        - Data Catalog: datacatalogmetastore
        - Data Flow: application
        - Data Flow: run
        - Data Integration: disworkspace
        - Data Labeling: datalabelingdataset
        - Data Safe: datasafeprivateendpoint
        - Data Science: datasciencejob
        - Data Science: datasciencejobrun
        - Data Science: datasciencemodel
        - Data Science: datasciencemodeldeployment
        - Data Science: datasciencenotebooksession
        - Data Science: datascienceproject
        - Database: autonomouscontainerdatabase
        - Database: autonomousdatabase
        - Database: autonomousvmcluster
        - Database: backupdestination
        - Database: cloudautonomousvmcluster
        - Database: cloudexadatainfrastructure
        - Database: cloudvmcluster
        - Database: database
        - Database: databasesoftwareimage
        - Database: dbhome
        - Database: dbkeystore
        - Database: dbnode
        - Database: dbserver
        - Database: dbsystem
        - Database: exadatainfrastructure
        - Database: externalcontainerdatabase
        - Database: externaldatabaseconnector
        - Database: externalnoncontainerdatabase
        - Database: externalpluggabledatabase
        - Database: pluggabledatabase
        - Database: vmcluster
        - Database: vmclusternetwork
        - Database Management: dbmgmtexternalasm
        - Database Management: dbmgmtexternalasminstance
        - Database Management: dbmgmtexternalcluster
        - Database Management: dbmgmtexternalclusterinstance
        - Database Management: dbmgmtexternaldbhome
        - Database Management: dbmgmtexternaldbnode
        - Database Management: dbmgmtexternaldbsystem
        - Database Management: dbmgmtexternaldbsystemconnector
        - Database Management: dbmgmtexternalexadatainfrastructure
        - Database Management: dbmgmtexternalexadatastorageconnector
        - Database Management: dbmgmtexternalexadatastoragegrid
        - Database Management: dbmgmtexternalexadatastorageserver
        - Database Management: dbmgmtexternallistener
        - Database Management: dbmgmtexternalmysqldb
        - Database Management: dbmgmtmysqldbconnector
        - Database Management: dbmgmtjob
        - Database Management: dbmgmtmanageddatabase
        - Database Management: dbmgmtmanageddatabasegroup
        - Database Management: dbmgmtnamedcredential
        - Database Management: dbmgmtprivateendpoint
        - Database Migration: agent
        - Database Migration: connection
        - Database Migration: job
        - Database Migration: migration
        - Database Tools: databasetoolsconnection
        - Database Tools: databasetoolsprivateendpoint
        - DevOps: devopsdeployartifact
        - DevOps: devopsdeployenvironment
        - DevOps: devopsdeployment
        - DevOps: devopsdeploypipeline
        - DevOps: devopsbuildpipeline
        - DevOps: devopsbuildpipelinestage
        - DevOps: devopsdeploystage
        - DevOps: devopsrepository
        - DevOps: devopsconnection
        - DevOps: devopstrigger
        - DevOps: devopsproject
        - Digital Assistant: odainstance
        - Email Delivery: emailsender
        - Email Delivery: emaildomain
        - Email Delivery: dkim
        - Events: eventrule
        - File Storage: filesystem
        - File Storage: mounttarget
        - File Storage with Lustre: lustrefilesystem
        - Fleet Application Management: famscatalogitem
        - Fleet Application Management: famscompliancepolicy
        - Fleet Application Management: famscompliancepolicyrule
        - Fleet Application Management: famsfleet
        - Fleet Application Management: famsmaintenancewindow
        - Fleet Application Management: famspatch
        - Fleet Application Management: famsplatformconfiguration
        - Fleet Application Management: famsproperty
        - Fleet Application Management: famsprovision
        - Fleet Application Management: famsrunbook
        - Fleet Application Management: famsschedulerdefinition
        - Fleet Application Management: famstaskrecord
        - Full Stack Disaster Recovery: drprotectiongroup
        - Full Stack Disaster Recovery: drplan
        - Full Stack Disaster Recovery: drplanexeuction
        - Functions: functionsapplication
        - Functions: functionsfunction
        - Globally Distributed Autonomous AI Database: osddistributedautonomousdb
        - Globally Distributed Autonomous AI Database: osddistributeddbprivateendpoint
        - Globally Distributed Exadata Database on Exascale Infrastructure: osddistributeddb
        - Globally Distributed Exadata Database on Exascale Infrastructure: osddistributeddbprivateendpoint
        - GoldenGate: goldengatedeployment
        - GoldenGate: goldengateconnection
        - IAM: compartment
        - IAM: group
        - IAM: identityprovider
        - IAM: policy
        - IAM: tagdefault
        - IAM: tagnamespace
        - IAM: user
        - Integration: integrationinstance
        - Java Management: jmsfleet
        - Java Management: jmsplugin
        - Kubernetes Engine: clusterscluster
        - Kubernetes Engine: clustersvirtualnodepool
        - Kubernetes Engine: clustersvirtualnode
        - Load Balancer: loadbalancer
        - Logging: log
        - Logging: loggroup
        - Logging: logsavedsearch
        - Logging: unifiedagentconfiguration
        - Management Agent: managementagent
        - Management Agent: managementagentinstallkey
        - Media Services (Media Flow): mediaworkflow
        - Media Services (Media Streams): streamdistributionchannel
        - Media Services (Media Streams): streampackagingconfig
        - Media Services (Media Streams): streamcdnconfig
        - Monitoring: alarm
        - Networking: byoiprange
        - Networking: cpe
        - Networking: crossconnect
        - Networking: crossconnectgroup
        - Networking: dhcpoptions
        - Networking: drg
        - Networking: internetgateway
        - Networking: ipsecconnection
        - Networking: ipv6
        - Networking: localpeeringgateway
        - Networking: natgateway
        - Networking: networksecuritygroup
        - Networking: publicip
        - Networking: publicippool
        - Networking: privateip
        - Networking: remotepeeringconnection
        - Networking: routetable
        - Networking: securitylist
        - Networking: servicegateway
        - Networking: subnet
        - Networking: vcn
        - Networking: virtualcircuit
        - Networking: vlan
        - Networking: vnic
        - Network Firewall: networkfirewall
        - Network Firewall: networkfirewallpolicy
        - NoSQL Database Cloud: nosqltable
        - Notifications: onssubscription
        - Notifications: onstopic
        - Object Storage: bucket
        - OCI Database with PostgreSQL: postgresqlbackup
        - OCI Database with PostgreSQL: postgresqlconfiguration
        - OCI Database with PostgreSQL: postgresqldbsystem
        - Oracle Cloud Bridge: OcbInventory
        - Oracle Cloud Bridge: OcbVmAsset
        - Oracle Cloud Bridge: OcbVmwareVmAsset
        - OS Management Hub: osmhlifecycleenvironment
        - OS Management Hub: osmhmanagedinstancegroup
        - OS Management Hub: osmhmanagementstation
        - OS Management Hub: osmhprofile
        - OS Management Hub: osmhscheduledjob
        - OS Management Hub: osmhsoftwaresource
        - Process Automation: OpaInstance
        - Queue: queue
        - Container Registry: containerimage
        - Container Registry: containerrepo
        - Resource Manager: ormconfigsourceprovider
        - Resource Manager: ormjob
        - Resource Manager: ormprivateendpoint
        - Resource Manager: ormstack
        - Resource Manager: ormtemplate
        - Search: consolerescourcecollections
        - Security Zones: securityzonessecurityzone
        - Security Zones: securityzonessecurityrecipe
        - Service Limits: quota
        - Streaming: connectharness
        - Streaming: stream
        - Vault: key
        - Vault: vault
        - Vault: vaultsecret
        - Visual Builder: visualbuilderinstance
        - Visual Builder Studio: vbsinstance
        - VMware solution: vmwareesxihost
        - VMware solution: vmwaresddc
        - Vulnerability Scanning: vsshostscanrecipe
        - Vulnerability Scanning: vsshostscantarget
        - Vulnerability Scanning: vsscontainerscanrecipe
        - Vulnerability Scanning: vsscontainerscantarget
        - WAF: httpredirect
        - WAF: waasaddresslist
        - WAF: waascertificate
        - WAF: waascustomprotectionrule
        - WAF: waaspolicy
        - WebLogic Management: WlmsWlsDomain
        - Zero Trust Packet Routing: securityattributenamespace
        - Zero Trust Packet Routing: zprpolicy

    Returns:
        List of resources with all additional fields.
    """
    # Use "all" if resource_type is not specified
    if resource_type is None or len(resource_type) < 3:
        resource_type = "all"
    
    # Build the query string
    if resource_type == "all":
        if compartment_ocid:
            structured_query = f"query all resources where compartmentId = '{compartment_ocid}'"
        else:
            structured_query = "query all resources"
    else:
        if compartment_ocid:
            structured_query = f"query {resource_type} resources where compartmentId = '{compartment_ocid}' return allAdditionalFields"
        else:
            structured_query = f"query {resource_type} resources return allAdditionalFields"
    print ("resource_type: ", resource_type)
    print ("structured_query: ", structured_query)
    search_client = oci_manager.get_client("resource_search")
    search_details = oci.resource_search.models.StructuredSearchDetails(
        query=structured_query,
        type="Structured"
    )
    results = oci.pagination.list_call_get_all_results(
        search_client.search_resources,
        search_details
    ).data
    return [_to_clean_dict(resource) for resource in results]


@mcp.tool()
def get_instance_details(instance_id: str) -> Dict[str, Any]:
    """Get detailed info for a Compute instance, including VNICs and public IPs.
    Args:
        instance_id: The OCID of the instance
    """
    compute = oci_manager.get_client("compute")
    vcn = oci_manager.get_client("network")
    inst = compute.get_instance(instance_id).data
    image = compute.get_image(inst.image_id).data
    print ("image: ", image)
    details: Dict[str, Any] = {
        "id": inst.id,
        "display_name": inst.display_name,
        "shape": inst.shape,
        "shape_config": inst.shape_config,
        "shape_config": (
                inst.shape_config.to_dict()
                if hasattr(inst.shape_config, "to_dict")
                else {
                    "burstable": getattr(inst.shape_config, "baseline_ocpu_utilization", None),
                    "ocpus": getattr(inst.shape_config, "ocpus", None),
                    "memory_in_gbs": getattr(inst.shape_config, "memory_in_gbs", None),
                    "vcpus": getattr(inst.shape_config, "vcpus", None),
                    "processor_description": getattr(inst.shape_config, "processor_description", None),
                    "gpus": getattr(inst.shape_config, "gpus", None),
                    "gpu_description": getattr(inst.shape_config, "gpu_description", None),
                }),
        "image": image.display_name,
        "operating_system": image.operating_system,
        "image_operating_system_version": image.operating_system_version,
        "lifecycle_state": inst.lifecycle_state,
        "time_created": inst.time_created.isoformat() if inst.time_created else None,
        "metadata": inst.metadata,
        "extended_metadata": inst.extended_metadata,
    }

    # VNIC attachments -> VNICs
    attachments = oci.pagination.list_call_get_all_results(
        compute.list_vnic_attachments,
        compartment_id=inst.compartment_id,
        instance_id=inst.id,
    ).data

    vnics = []
    for att in attachments:
        vnic = vcn.get_vnic(att.vnic_id).data
        vnics.append({
            "id": vnic.id,
            "display_name": vnic.display_name,
            "hostname_label": vnic.hostname_label,
            "private_ip": vnic.private_ip,
            "public_ip": vnic.public_ip,
            "subnet_id": vnic.subnet_id,
            "is_primary": vnic.is_primary,
        })
    details["vnics"] = vnics
    return details


@mcp.tool()
def instance_action(instance_id: str, action: str) -> Dict[str, Any]:
    """Perform a safe instance action (START, STOP, RESET, SOFTRESET, SOFTSTOP).
    Args:
        instance_id: Instance OCID
        action: One of START, STOP, RESET, SOFTRESET, SOFTSTOP
    """
    compute = oci_manager.get_client("compute")
    action = action.upper()
    valid = {"START","STOP","RESET","SOFTRESET","SOFTSTOP"}
    if action not in valid:
        raise ValueError(f"Invalid action '{action}'. Allowed: {sorted(valid)}")
    resp = compute.instance_action(instance_id=instance_id, action=action)
    return {"status": resp.status, "headers": dict(resp.headers)}


@mcp.tool()
def list_autonomous_databases(compartment_ocid: Optional[str] = None) -> List[Dict[str, Any]]:
    """List Autonomous Databases in a compartment (defaults to tenancy)."""
    comp = compartment_ocid or _default_compartment()
    assert comp, "No compartment OCID available"
    db = oci_manager.get_client("database")
    items = []
    for adb in oci.pagination.list_call_get_all_results(
        db.list_autonomous_databases, compartment_id=comp
    ).data:
        items.append({
            "id": adb.id,
            "db_name": adb.db_name,
            "display_name": adb.display_name,
            "lifecycle_state": adb.lifecycle_state,
            "db_workload": adb.db_workload,
            "cpu_core_count": getattr(adb, "cpu_core_count", None),
            "data_storage_size_in_tbs": getattr(adb, "data_storage_size_in_tbs", None),
            "is_auto_scaling_enabled": getattr(adb, "is_auto_scaling_enabled", None),
            "connection_strings": _to_clean_dict(getattr(adb, "connection_strings", {})),
        })
    return items


@mcp.tool()
def list_db_systems(compartment_ocid: Optional[str] = None) -> List[Dict[str, Any]]:
    """List DB Systems (Bare Metal and Virtual Machine databases) in a compartment (defaults to tenancy)."""
    comp = compartment_ocid or _default_compartment()
    assert comp, "No compartment OCID available"
    db = oci_manager.get_client("database")
    items = []
    for dbs in oci.pagination.list_call_get_all_results(
        db.list_db_systems, compartment_id=comp
    ).data:
        items.append({
            "id": dbs.id,
            "display_name": dbs.display_name,
            "lifecycle_state": dbs.lifecycle_state,
            "shape": dbs.shape,
            "database_edition": getattr(dbs, "database_edition", None),
            "hostname": getattr(dbs, "hostname", None),
            "domain": getattr(dbs, "domain", None),
            "cpu_core_count": getattr(dbs, "cpu_core_count", None),
            "node_count": getattr(dbs, "node_count", None),
            "time_created": dbs.time_created.isoformat() if dbs.time_created else None,
        })
    return items


@mcp.tool()
def list_storage_buckets(compartment_ocid: Optional[str] = None) -> List[Dict[str, Any]]:
    """List Object Storage buckets in the configured region for the given compartment."""
    comp = compartment_ocid or _default_compartment()
    assert comp, "No compartment OCID available"
    osvc = oci_manager.get_client("object_storage")
    namespace = osvc.get_namespace().data
    buckets = oci.pagination.list_call_get_all_results(
        osvc.list_buckets, namespace_name=namespace, compartment_id=comp
    ).data
    return [{"name": b.name, "created": b.time_created.isoformat(), "namespace": namespace} for b in buckets]


@mcp.tool()
def list_compartments() -> List[Dict[str, Any]]:
    """List accessible compartments in the tenancy (including subtrees)."""
    identity = oci_manager.get_client("identity")
    tenancy_id = oci_manager.config["tenancy"]
    comps = oci.pagination.list_call_get_all_results(
        identity.list_compartments,
        compartment_id=tenancy_id,
        compartment_id_in_subtree=True,
        access_level="ACCESSIBLE",
    ).data
    return [{"id": c.id, "name": c.name, "lifecycle_state": c.lifecycle_state, "is_accessible": c.is_accessible} for c in comps]


@mcp.tool()
def perform_security_assessment(compartment_ocid: Optional[str] = None) -> Dict[str, Any]:
    """Basic security posture checks (public IPs, wide-open rules). Read-only heuristics."""
    comp = compartment_ocid or _default_compartment()
    assert comp, "No compartment OCID available"

    compute = oci_manager.get_client("compute")
    net = oci_manager.get_client("network")

    findings: Dict[str, Any] = {"public_instances": [], "wide_open_nsg_rules": [], "wide_open_sec_list_rules": []}

    # Instances with public IPs
    for inst in oci.pagination.list_call_get_all_results(compute.list_instances, compartment_id=comp).data:
        vnic_atts = oci.pagination.list_call_get_all_results(
            compute.list_vnic_attachments, compartment_id=comp, instance_id=inst.id
        ).data
        for att in vnic_atts:
            vnic = net.get_vnic(att.vnic_id).data
            if vnic.public_ip:
                findings["public_instances"].append({"instance_id": inst.id, "name": inst.display_name, "public_ip": vnic.public_ip})

    # Security Lists allowing 0.0.0.0/0 inbound
    for vcn in oci.pagination.list_call_get_all_results(net.list_vcns, compartment_id=comp).data:
        sec_lists = oci.pagination.list_call_get_all_results(net.list_security_lists, compartment_id=comp, vcn_id=vcn.id).data
        for sl in sec_lists:
            for rule in sl.ingress_security_rules or []:
                src = getattr(rule, "source", "")
                if src == "0.0.0.0/0":
                    findings["wide_open_sec_list_rules"].append({"security_list_id": sl.id, "vcn": vcn.display_name, "proto": rule.protocol})

        # NSGs
        nsgs = oci.pagination.list_call_get_all_results(net.list_network_security_groups, compartment_id=comp, vcn_id=vcn.id).data
        for nsg in nsgs:
            rules = oci.pagination.list_call_get_all_results(net.list_network_security_group_security_rules, network_security_group_id=nsg.id).data
            for r in rules:
                src = getattr(r, "source", "") or getattr(r, "source_type", "")
                if getattr(r, "direction", "INGRESS") == "INGRESS" and getattr(r, "source", "") == "0.0.0.0/0":
                    findings["wide_open_nsg_rules"].append({"nsg_id": nsg.id, "name": nsg.display_name, "proto": r.protocol})

    return findings


@mcp.tool()
def get_tenancy_cost_summary(start_time_iso: Optional[str] = None,
                             end_time_iso: Optional[str] = None,
                             granularity: str = "DAILY") -> Dict[str, Any]:
    """Summarize tenancy costs using Usage API (requires permissions).
    Args:
        start_time_iso: ISO8601 start (defaults: now-7d)
        end_time_iso: ISO8601 end (defaults: now)
        granularity: DAILY or MONTHLY
    """
    try:
        usage = oci_manager.get_client("usage_api")
    except Exception as e:
        raise RuntimeError("Usage API not available; upgrade OCI SDK and permissions.") from e

    if not end_time_iso:
        end = datetime.now(timezone.utc)
    else:
        end = datetime.fromisoformat(end_time_iso.replace("Z",""))
    if not start_time_iso:
        start = end - timedelta(days=7)
    else:
        start = datetime.fromisoformat(start_time_iso.replace("Z",""))

    tenant_id = oci_manager.config["tenancy"]
    details = oci.usage_api.models.RequestSummarizedUsagesDetails(
        tenant_id=tenant_id,
        time_usage_started=start,
        time_usage_ended=end,
        granularity=granularity,
        query_type="COST",
        group_by=["service"],
        # forecast=oci.usage_api.models.Forecast(),
    )
    resp = usage.request_summarized_usages(request_summarized_usages_details=details)
    rows = [to_dict(x) for x in resp.data.items] if getattr(resp.data, "items", None) else []
    total = sum((r.get("computed_amount", 0) or 0) for r in rows)
    return {"start": start.isoformat()+"Z", "end": end.isoformat()+"Z", "granularity": granularity, "total_computed_amount": total, "items": rows}


@mcp.tool()
def get_resource_audit_events(resource_ocid: str,
                               days_back: Optional[int] = None) -> List[Dict[str, Any]]:
    """Get historic actions (audit events) for a specific OCI resource.
    Only returns write operations: PUT, POST, PATCH, DELETE.
    Uses OCI Logging Search API to query audit logs.
    
    IMPORTANT: The OCI Logging Search API has a maximum time range limit of 14 days.
    If days_back exceeds 14, it will be automatically capped at 14 days.
    
    Args:
        resource_ocid: The OCID of the resource to query audit events for
        days_back: Number of days back in history to search (defaults to 14, maximum is 14)
    Returns:
        List of audit events with event details (eventTime, eventName, requestAction, principalId, etc.)
    """
    try:
        log_search_client = oci_manager.get_client("logging_search")
    except Exception as e:
        raise RuntimeError("Logging Search service not available; check OCI SDK version and permissions.") from e

    # Find the resource's compartment OCID using structured search
    try:
        search_client = oci_manager.get_client("resource_search")
        
        # Extract resource type from OCID (format: ocid1.<resource_type>.<region>...)
        # Example: ocid1.instance.oc1.eu-frankfurt-1... -> resource_type = "instance"
        ocid_parts = resource_ocid.split(".")
        if len(ocid_parts) < 2:
            raise ValueError(f"Invalid OCID format: {resource_ocid}")
        
        resource_type = ocid_parts[1]  # Second part is the resource type
        
        # Search for resources of this type
        structured_query = f"query {resource_type} resources return allAdditionalFields"
        search_details = oci.resource_search.models.StructuredSearchDetails(
            query=structured_query,
            type="Structured"
        )
        search_results = oci.pagination.list_call_get_all_results(
            search_client.search_resources,
            search_details
        ).data
        
        # Filter results to find the exact resource by identifier
        matching_resource = None
        for result in search_results:
            resource_data = _to_clean_dict(result)
            resource_id = resource_data.get("identifier") or resource_data.get("id")
            if resource_id == resource_ocid:
                matching_resource = resource_data
                break
        
        if not matching_resource:
            raise ValueError(f"Resource with OCID {resource_ocid} not found")
        
        # Get compartment_id from the matching resource
        comp = matching_resource.get("compartment_id") or matching_resource.get("compartmentId")
        
        if not comp:
            raise ValueError(f"Could not determine compartment OCID for resource {resource_ocid}")
        
        log.info(f"Found resource in compartment {comp}")
        
    except Exception as e:
        raise RuntimeError(f"Failed to find resource {resource_ocid} using structured search: {e}") from e

    # Enforce 14-day maximum limit for OCI Logging Search API
    MAX_SEARCH_DAYS = 14
    
    # Set default to 14 days if not specified, and ensure it never exceeds 14
    if days_back is None:
        days_back = MAX_SEARCH_DAYS
    elif days_back > MAX_SEARCH_DAYS:
        log.warning(
            f"Requested days_back ({days_back}) exceeds OCI Logging Search API limit "
            f"of {MAX_SEARCH_DAYS} days. Capping to {MAX_SEARCH_DAYS} days."
        )
        days_back = MAX_SEARCH_DAYS
    
    # Calculate start and end times automatically
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)
    
    # Build search query to filter by resource OCID and HTTP methods
    # OCI Logging Search query format: search "compartment_ocid/_Audit" | filter conditions | sort
    write_methods = ["POST", "PUT", "PATCH", "DELETE"]
    
    # Build the action filter: (data.request.action='POST' or data.request.action='PUT' or ...)
    action_filters = " or ".join([f"data.request.action='{method}'" for method in write_methods])
    
    # Construct the search query matching the OCI Logging Search format
    # Search in compartment audit logs, filter by action type and resource OCID in logContent
    search_query = f'search "{comp}/_Audit" | ({action_filters}) and (logContent=\'*{resource_ocid}*\') | sort by datetime desc'
    
    events = []
    
    try:
        # Create SearchLogsDetails object
        search_details = oci.loggingsearch.models.SearchLogsDetails(
            time_start=start,
            time_end=end,
            search_query=search_query
        )
        
        # Execute the search using LogSearchClient
        response = log_search_client.search_logs(search_details)
        
        # Process the results
        if hasattr(response.data, 'results') and response.data.results:
            for result in response.data.results:
                if hasattr(result, 'data'):
                    event_data = _to_clean_dict(result.data)
                    # Ensure resource_ocid is included
                    event_data["resource_id"] = resource_ocid
                    # Extract HTTP method from requestAction if available
                    request_action = event_data.get("requestAction", "") or event_data.get("request_action", "")
                    if request_action:
                        method = request_action.split()[0] if request_action else ""
                        event_data["http_method"] = method
                    events.append(event_data)
        
    except Exception as e:
        raise RuntimeError(f"Failed to query audit events for resource {resource_ocid}: {e}") from e

    # Sort by event time (most recent first)
    def get_event_time(event):
        time_fields = ["event_time", "eventTime", "time", "timestamp"]
        for field in time_fields:
            if field in event:
                val = event[field]
                if isinstance(val, datetime):
                    return val
                elif isinstance(val, str):
                    try:
                        return datetime.fromisoformat(val.replace("Z", "+00:00"))
                    except:
                        return datetime.min
        return datetime.min
    
    events.sort(key=get_event_time, reverse=True)
    
    # Convert datetime objects to ISO strings for JSON serialization
    for event in events:
        for key, val in event.items():
            if isinstance(val, datetime):
                event[key] = val.isoformat()
    
    return events


# ----------- Resources -----------

@mcp.resource("oci://compartments")
def resource_compartments() -> Dict[str, Any]:
    """Resource listing compartments (id, name)."""
    return {"compartments": list_compartments()}


# ----------- Prompts -----------

@mcp.prompt("oci_analysis_prompt")
def oci_analysis_prompt() -> str:
    """A helper prompt to analyze OCI state returned by the tools."""
    return (
        "You are an expert Oracle Cloud architect. Given the JSON outputs from tools like "
        "`list_compute_instances`, `perform_security_assessment`, and `get_tenancy_cost_summary`, "
        "produce a concise assessment covering security, cost, and reliability. "
        "Highlight risky public exposure, suggest least-privilege hardening, recommend cost optimizations "
        "(stop idle instances, enable ADB auto-scaling), and note any missing monitoring/alerts."
    )


def main() -> None:
    mcp.run(transport="http", port=8000, path="/ocimcp")


if __name__ == "__main__":
    main()

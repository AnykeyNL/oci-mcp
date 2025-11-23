# OCI MCP Server

Model Context Protocol (MCP) server exposing **Oracle Cloud Infrastructure** tools, resources and prompts.

Basic framework taken from: https://github.com/karthiksuku/oci-mcp 

- 🔧 Tools: 

  - list_compartments: List accessible compartments
  - list_compute_instances: List Compute instances and details
  - list_db_systems: List DB systems (Bare Metal/VM)
  - list_adb_databases: List Autonomous Databases
  - list_storage_buckets: List Object Storage buckets
  - perform_security_assessment: Basic security posture checks (public IPs, wide-open rules)
  - get_tenancy_cost_summary: Summarize tenancy costs using Usage API
  - search_oci_resources: Search/find any OCI resource by resource type
  - get_instance_details: Get full details for a Compute instance
  - get_resource_audit_events: Historic actions (audit events) for a resource

- 📚 Resources: `oci://compartments` etc.
- 🧠 Prompts: `oci_analysis_prompt`
- 🖥️ Suggest to use Cursor with buildin MCP support to test

> Built with the [FastMCP Python SDK](https://gofastmcp.com/) and the [OCI Python SDK](https://oracle-cloud-infrastructure-python-sdk.readthedocs.io).

## Quick start

See [`examples/sample_queries.md`](examples/sample_queries.md) for ideas.

## Configuration

- Uses `~/.oci/config` by default (created via `oci setup config`).
- Can also read explicit env vars from `.env` (see `.env.example`).
- Optional: `DEFAULT_COMPARTMENT_OCID` to scope queries.

## Notes

- Cost summary uses the Usage API if available.

## License

MIT

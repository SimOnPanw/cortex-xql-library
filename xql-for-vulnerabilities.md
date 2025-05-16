# XQL For Vulnerability management

Search for "dataset = va_cves"

```bash
dataset = va_cves
| filter (severity = ENUM.CRITICAL or severity = ENUM.HIGH) and exploitability_score >= 1
| arrayexpand affected_hosts
| comp count(name) as Total_CVE_per_host by affected_hosts
| view graph type = pie xaxis = affected_hosts yaxis = Total_CVE_per_host
```

Count the CVE per severity - Graph view
```bash
dataset = va_cves
| alter current_day = extract_time(current_time(), "DAY")
| alter td = timestamp_diff(current_time(), publication_date , "DAY")
| filter td> current_day
| comp count(name) by severity 
| alter severity_enum_value = to_string(severity)
| sort desc  severity_enum_value
| view graph type = pie xaxis = severity yaxis = count_1
```

```bash
dataset = va_endpoints 
|join (dataset = endpoints 
    |fields endpoint_name, domain, platform
    ) as hi_a hi_a.endpoint_name = endpoint_name 
|arrayexpand cves 
|join (dataset=va_cves 
|fields affected_products, name) as cve_va cve_va.name = cves
```

With the cloud account:
```bash
dataset = va_endpoints 
|join (dataset = endpoints 
    | alter CloudAccount = json_extract_scalar(cloud_info , "$.project_id")
    |fields endpoint_name, domain, platform, cloud_id, CloudAccount 
    ) as hi_a hi_a.endpoint_name = endpoint_name 
|arrayexpand cves 
|join (dataset=va_cves 
|fields affected_products, name) as cve_va cve_va.name = cves
```


With the cloudaccounts as parameter, search for `"__AWS_CLOUD_ACCOUNT__"`
```bash
dataset = va_endpoints 
|join (dataset = endpoints 
    | alter CloudAccount = json_extract_scalar(cloud_info , "$.project_id")
    |fields endpoint_name, domain, platform, cloud_id, CloudAccount , cloud_info
    ) as hi_a hi_a.endpoint_name = endpoint_name 
| arrayexpand cves 
| join (dataset=va_cves 
| fields affected_products, name) as cve_va cve_va.name = cves
| filter CloudAccount in ($cloudAccounts) 
```


```bash
dataset = va_cves
| arrayexpand affected_hosts
| arrayexpand affected_products 
| join type = left (preset = host_inventory | fields endpoint_name, manufacturer, model) as host_inv affected_hosts = host_inv.endpoint_name 
| fields endpoint_name, name, affected_products, severity_score, impact_score
| sort desc impact_score 
```


```bash
dataset = va_endpoints 
|join (dataset = endpoints 
    | alter CloudAccount = json_extract_scalar(cloud_info , "$.project_id")
    |fields endpoint_name, domain, platform, cloud_id, CloudAccount 
    ) as hi_a hi_a.endpoint_name = endpoint_name 
|arrayexpand cves 
|join (dataset=va_cves 
|fields affected_products, name) as cve_va cve_va.name = cves
| comp count(name) as Total_CVE_per_CloudAccounts by CloudAccount
```


```bash
dataset = va_endpoints 
|join (dataset = endpoints 
    | alter CloudAccount = json_extract_scalar(cloud_info , "$.project_id")
    |fields endpoint_name, domain, platform, cloud_id, CloudAccount 
    ) as hi_a hi_a.endpoint_name = endpoint_name 
|arrayexpand cves 
|join (dataset = findings 
| filter (xdm.finding.category = """VULNERABILITY""") 

```

```bash
dataset = issues 
| fields xdm.issue.id, xdm.issue.severity 
| join (dataset = findings | fields xdm.finding.name, xdm.finding.category) as x x.xdm.finding.name != "" 
```

```bash
dataset = findings 
| filter (xdm.finding.category = """VULNERABILITY""") 
| alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
| join (
    dataset = asset_inventory      
    | filter xdm.asset.type.category in ("VM Instance", "Image", "Kubernetes Cluster") 
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id
| comp count(name) as Total_CVE_per_CloudAccounts by CloudAccount
``
## With EPSS
```bash
dataset = findings 
| filter (xdm.finding.category = """VULNERABILITY""") 
| alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
| alter severity = xdm.finding.normalized_fields -> ["xdm.vulnerability.severity"]
| alter cvss_score = xdm.finding.normalized_fields -> ["xdm.vulnerability.cvss_score"]
| alter has_a_fix = xdm.finding.normalized_fields -> ["xdm.vulnerability.has_a_fix"]
| filter xdm.finding.owner = "CWP"
| join (
    dataset = asset_inventory      
    | filter xdm.asset.type.category in ("VM Instance", "Kubernetes Cluster") 
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id
| fields  xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name, xdm.asset.provider, xdm.asset.realm, cve_id, severity, cvss_score, has_a_fix 
| filter severity = "Critical"
| join (
    dataset=va_cves 
    | fields affected_products, name, exploitability_score AS EPSS
) as cve_va cve_va.name = cve_id 
```

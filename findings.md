```bash

dataset = findings 
| filter (xdm.finding.category = "VULNERABILITY") 
| alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
| join (
    dataset = asset_inventory  
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id

```


```bash
dataset = findings 
| filter (xdm.finding.category = "VULNERABILITY") 
| alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
| join (
    dataset = asset_inventory      
    | filter xdm.asset.type.category in ("VM Instance", "Image", "Kubernetes Cluster") 
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id
| comp count(cve_id) as Total_CVE_per_CloudAccounts by xdm.asset.realm
| sort desc Total_CVE_per_CloudAccounts
```


```bash
dataset = findings 
| filter (xdm.finding.category = "VULNERABILITY") 
| alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
| join (
    dataset = asset_inventory      
    | filter xdm.asset.type.category in ("VM Instance", "Image", "Kubernetes Cluster") 
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id
| comp count(cve_id) as Total_CVE_per_Assets by xdm.asset.name, xdm.asset.type.name
| sort desc Total_CVE_per_Assets
```

```bash
dataset = findings 
| filter (xdm.finding.category = "VULNERABILITY") 
| alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
| join (
    dataset = asset_inventory      
    | filter xdm.asset.type.category in ("VM Instance", "Image", "Kubernetes Cluster") 
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id
| comp count(cve_id) as Total_CVE_per_Assets by xdm.asset.name, xdm.asset.realm,  xdm.asset.type.name
| sort desc Total_CVE_per_Assets
```


```bash
dataset = findings 
| filter (xdm.finding.category = "VULNERABILITY") 
| alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
| join (
    dataset = asset_inventory      
    | filter xdm.asset.type.category in ("VM Instance", "Image", "Kubernetes Cluster") 
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id
| comp count(cve_id) as Total_CVE_per_Assets by xdm.asset.name, xdm.asset.realm,  xdm.asset.type.name
| sort desc Total_CVE_per_Assets
| filter xdm.asset.realm in ($cloudacount)
```


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
| filter severity = "Critical"
| fields  xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name, xdm.asset.provider, xdm.asset.realm, cve_id, severity, cvss_score, has_a_fix 
```


```
dataset = findings 
| filter (xdm.finding.category = """VULNERABILITY""") 
| alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
| alter severity = xdm.finding.normalized_fields -> ["xdm.vulnerability.severity"]
| join (
    dataset = asset_inventory      
    | filter xdm.asset.type.category in ("VM Instance", "Kubernetes Cluster") 
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id
| filter severity = "Critical"

| comp count(cve_id) as Total_Critical_CVE_per_Instance by xdm.finding.asset_name
| sort desc Total_Critical_CVE_per_Instance
```

Or the graph view
```
dataset = findings 
| filter (xdm.finding.category = """VULNERABILITY""") 
| alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
| alter severity = xdm.finding.normalized_fields -> ["xdm.vulnerability.severity"]
| join (
    dataset = asset_inventory      
    | filter xdm.asset.type.category in ("VM Instance", "Kubernetes Cluster") 
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id
| filter severity = "Critical"

| comp count(cve_id) as Total_Critical_CVE_per_Instance by xdm.finding.asset_name
| sort desc Total_Critical_CVE_per_Instance
```


```
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
| filter severity = "Critical"
| fields  xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name, xdm.asset.provider, xdm.asset.realm, cve_id, severity, cvss_score, has_a_fix
```

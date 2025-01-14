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
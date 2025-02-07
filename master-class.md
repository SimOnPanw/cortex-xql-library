# XQL Master Class

## Documentation

[Get started with XQL](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Get-started-with-XQL)

## Get Asset inventory

```bash
dataset = asset_inventory 
```

```bash
dataset = asset_inventory 
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "EC2 Instance"
```

```bash
dataset = asset_inventory 
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "Container Image"
```
## Query JSON Parameters

```bash
dataset = asset_inventory 
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "Container Image"
| alter name = json_extract_scalar(xdm.asset.normalized_fields, "$.CWP['xdm.asset.name']")
| alter layers = json_extract_array(xdm.asset.normalized_fields, "$.CWP['xdm.image.layers']")
| arrayexpand layers 
| alter instruction = json_extract_scalar(layers, "$.instructions")
| fields name, instruction, layers 
```

## Join with Findings dataset

```bash
dataset = asset_inventory 
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "Container Image"
| alter name = json_extract_scalar(xdm.asset.normalized_fields, "$.CWP['xdm.asset.name']")
| alter layers = json_extract_array(xdm.asset.normalized_fields, "$.CWP['xdm.image.layers']")
| arrayexpand layers 
| alter instruction = json_extract_scalar(layers, "$.instructions")
| fields xdm.asset.id, name, instruction, layers 
| join (dataset = findings) as findings xdm.asset.id = findings.xdm.finding.asset_id 
```

## Add filters to the join
```bash
dataset = asset_inventory 
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "Container Image"
| alter name = json_extract_scalar(xdm.asset.normalized_fields, "$.CWP['xdm.asset.name']")
| alter layers = json_extract_array(xdm.asset.normalized_fields, "$.CWP['xdm.image.layers']")
| arrayexpand layers 
| alter instruction = json_extract_scalar(layers, "$.instructions")
| fields xdm.asset.id, name, instruction, layers 
| join (dataset = findings 
    | filter (xdm.finding.category = "VULNERABILITY") 
    | alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
) as findings xdm.asset.id = findings.xdm.finding.asset_id 
| fields name, instruction, cve_id
```

## Add computation

```bash
dataset = asset_inventory 
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "Container Image"
| alter name = json_extract_scalar(xdm.asset.normalized_fields, "$.CWP['xdm.asset.name']")
| fields xdm.asset.id, name
| join (dataset = findings 
    | filter (xdm.finding.category = "VULNERABILITY") 
    | alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
) as findings xdm.asset.id = findings.xdm.finding.asset_id 
| comp count(cve_id) as TotalVulnerabilities by name 
| sort desc TotalVulnerabilities 
```

Other example:  

```bash
dataset = findings 
| join (
    dataset = asset_inventory      
    | filter xdm.asset.type.category in ("VM Instance", "Image", "Kubernetes Cluster") 
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id
| comp count(xdm.asset.id) as Total_Findings by xdm.asset.name, xdm.asset.type.name, xdm.finding.category
| sort desc xdm.asset.name
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

## AWS confused deputy problem

```bash
dataset = asset_inventory 
| filter xdm.asset.type.id = "AWS_IAM_ROLE" 
| alter statements = json_extract_array(xdm.asset.raw_fields, "$['Platform Discovery'].Role.AssumeRolePolicyDocument.Statement") 
| arrayexpand statements | alter principal = json_extract(statements, "$.Principal") 
| alter aws_statement = json_extract_scalar(principal, "$.AWS") 
| alter myaccount = arrayindex( regextract(aws_statement, "([0-9]{12})"), 0) 
| filter aws_statement = "*" | filter myaccount not in (dataset = asset_inventory | filter xdm.asset.provider = "aws" | alter aws_account = xdm.asset.realm | dedup aws_account | fields aws_account)
```

Link to the AWS Documentation: [AWS confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)


## Create a lookup dataset

```bash
dataset = asset_inventory 
| filter xdm.asset.provider = "aws" 
| alter aws_account = xdm.asset.realm 
| dedup aws_account 
| fields aws_account 
| target type = lookup append = false aws_cloud_accounts_lookup 
```
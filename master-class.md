# XQL Master Class

## Documentation

[https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Get-started-with-XQL](Get started with XQL)

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

Link of documentation: [https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html](AWS confused deputy problem)


## Create a lookup dataset

```bash
dataset = asset_inventory 
| filter xdm.asset.provider = "aws" 
| alter aws_account = xdm.asset.realm 
| dedup aws_account 
| fields aws_account 
| target type = lookup append = false aws_cloud_accounts_lookup 
```
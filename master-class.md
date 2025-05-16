# XQL Master Class

Welcome to the **XQL Master Class** workshop.

---

## Table of Contents
1. [Documentation](#documentation)  
2. [Asset Inventory Queries](#asset-inventory-queries)  
3. [Querying JSON Parameters](#querying-json-parameters)  
4. [Joining with the Findings Dataset](#joining-with-the-findings-dataset)  
5. [Filtering a Join](#filtering-a-join)  
6. [Adding Computations](#adding-computations)  
7. [Other Query Examples](#other-query-examples)  
8. [AWS Confused Deputy Problem](#aws-confused-deputy-problem)  
9. [Creating a Lookup Dataset](#creating-a-lookup-dataset)  

---

## Documentation

If you are new to XQL or want more detailed information, see:  
[Get started with XQL](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Get-started-with-XQL)

---

## Asset Inventory Queries

Below are some simple queries to retrieve data from the **asset_inventory** dataset.

```bash
dataset = asset_inventory
```

**Explanation**:  
- Returns all assets in your inventory.

### Filtering by Provider and Type

```bash
dataset = asset_inventory
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "EC2 Instance"
```

**Explanation**:  
- Filters assets to only those whose provider is AWS and whose type is EC2 Instance.

```bash
dataset = asset_inventory
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "Container Image"
```

**Explanation**:  
- Filters assets to only those whose provider is AWS and whose type is Container Image.

---

## Querying JSON Parameters

Sometimes the `xdm.asset.normalized_fields` or `xdm.asset.raw_fields` contain JSON objects or arrays. Here is an example of how to extract data from JSON fields.

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

**Key Points**:  
- **json_extract_scalar** pulls a single scalar value from a JSON path.  
- **json_extract_array** pulls an array of items from a JSON path.  
- **arrayexpand** expands array elements into separate rows.

---

## Joining with the Findings Dataset

Often, you’ll need to combine data from multiple datasets. For example, combining **asset_inventory** with **findings**.

```bash
dataset = asset_inventory
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "Container Image"
| alter name = json_extract_scalar(xdm.asset.normalized_fields, "$.CWP['xdm.asset.name']")
| alter layers = json_extract_array(xdm.asset.normalized_fields, "$.CWP['xdm.image.layers']")
| arrayexpand layers
| alter instruction = json_extract_scalar(layers, "$.instructions")
| fields xdm.asset.id, name, instruction, layers
| join (
    dataset = findings
) as findings xdm.asset.id = findings.xdm.finding.asset_id
```

**Explanation**:  
- Selects AWS Container Images from the **asset_inventory** dataset.  
- Extracts relevant JSON fields into columns (`name`, `layers`, `instruction`).  
- Joins with the **findings** dataset on matching `asset_id`.

---

## Filtering a Join

You can add filters inside a join to return specific types of findings—e.g., only vulnerabilities.

```bash
dataset = asset_inventory
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "Container Image"
| alter name = json_extract_scalar(xdm.asset.normalized_fields, "$.CWP['xdm.asset.name']")
| alter layers = json_extract_array(xdm.asset.normalized_fields, "$.CWP['xdm.image.layers']")
| arrayexpand layers
| alter instruction = json_extract_scalar(layers, "$.instructions")
| fields xdm.asset.id, name, instruction, layers
| join (
    dataset = findings
    | filter xdm.finding.category = "VULNERABILITY"
    | alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
) as findings xdm.asset.id = findings.xdm.finding.asset_id
| fields name, instruction, cve_id
```

**Explanation**:  
- Join sub-query filters only vulnerability findings.  
- Extracts the `cve_id` from JSON data.  
- Final output shows `name`, `instruction`, and `cve_id`.

---

## Adding Computations

Use the **comp** command to perform aggregations (counts, sums, averages, etc.).

```bash
dataset = asset_inventory
| filter xdm.asset.provider = "AWS"
| filter xdm.asset.type.name = "Container Image"
| alter name = json_extract_scalar(xdm.asset.normalized_fields, "$.CWP['xdm.asset.name']")
| fields xdm.asset.id, name
| join (
    dataset = findings
    | filter xdm.finding.category = "VULNERABILITY"
    | alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
) as findings xdm.asset.id = findings.xdm.finding.asset_id
| comp count(cve_id) as TotalVulnerabilities by name
| sort desc TotalVulnerabilities
```

**Explanation**:  
- After joining with **findings**, this query **counts** CVE IDs per image `name`.  
- Sorts results in descending order to highlight the most vulnerable assets first.

---

## Other Query Examples

Below are two additional examples that demonstrate how to combine **asset_inventory** and **findings** in different ways.

### Example A

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

**Explanation**:  
- Joins **findings** with selected asset categories (`VM Instance`, `Image`, `Kubernetes Cluster`).  
- Counts total findings for each asset and finding category.

### Example B

```bash
dataset = findings
| filter xdm.finding.category = "VULNERABILITY"
| alter cve_id = xdm.finding.normalized_fields -> ["xdm.vulnerability.cve_id"]
| join (
    dataset = asset_inventory
    | filter xdm.asset.type.category in ("VM Instance", "Image", "Kubernetes Cluster")
    | fields xdm.asset.id, xdm.asset.type.category, xdm.asset.type.class, xdm.asset.realm, xdm.asset.provider, xdm.asset.name, xdm.asset.type.id, xdm.asset.type.name
) as asset asset.xdm.asset.id = xdm.finding.asset_id
| comp count(cve_id) as Total_CVE_per_Assets by xdm.asset.name, xdm.asset.type.name
| sort desc Total_CVE_per_Assets
```

**Explanation**:  
- Filters only vulnerability findings.  
- Extracts CVE IDs.  
- Joins with relevant assets.  
- Counts the number of CVEs per asset.

---

## AWS Confused Deputy Problem

For more details, see the [AWS confused deputy problem documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).  
The query below helps identify potential misconfigurations in AWS IAM roles:

```bash
dataset = asset_inventory
| filter xdm.asset.type.id = "AWS_IAM_ROLE"
| alter statements = json_extract_array(xdm.asset.raw_fields, "$['Platform Discovery'].Role.AssumeRolePolicyDocument.Statement")
| arrayexpand statements
| alter principal = json_extract(statements, "$.Principal")
| alter aws_statement = json_extract_scalar(principal, "$.AWS")
| alter myaccount = arrayindex( regextract(aws_statement, "([0-9]{12})"), 0)
| filter aws_statement = "*"
| filter myaccount not in (
    dataset = asset_inventory
    | filter xdm.asset.provider = "aws"
    | alter aws_account = xdm.asset.realm
    | dedup aws_account
    | fields aws_account
)
```

**Explanation**:  
- Looks for IAM roles with an `AssumeRolePolicyDocument` that has a principal set to `*`.  
- Compares the extracted account ID against known AWS accounts, exposing any roles potentially open to external accounts.

---

## Creating a Lookup Dataset

You can save intermediate results as a lookup dataset for reuse in future queries:

```bash
dataset = asset_inventory
| filter xdm.asset.provider = "aws"
| alter aws_account = xdm.asset.realm
| dedup aws_account
| fields aws_account
| target type = lookup append = false aws_cloud_accounts_lookup
```

**Explanation**:  
- Filters for AWS assets and collects each unique `aws_account`.  
- Saves it as a lookup named `aws_cloud_accounts_lookup`.  
- This lookup can then be used in subsequent queries for filtering or joins.

---

**Happy Querying!**

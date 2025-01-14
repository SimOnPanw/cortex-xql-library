# XQL For Vulnerability management

Search for "dataset = va_cves "

Count the CVE per severity - Graph view
```
dataset = va_cves
| alter current_day = extract_time(current_time(), "DAY")
| alter td = timestamp_diff(current_time(), publication_date , "DAY")
| filter td> current_day
| comp count(name) by severity 
| alter severity_enum_value = to_string(severity)
| sort desc  severity_enum_value
| view graph type = pie xaxis = severity yaxis = count_1
```

```
dataset = va_endpoints 
|join (dataset = endpoints 
    |fields endpoint_name, domain, platform
    ) as hi_a hi_a.endpoint_name = endpoint_name 
|arrayexpand cves 
|join (dataset=va_cves 
|fields affected_products, name) as cve_va cve_va.name = cves
```

With the cloud account:
```
dataset = va_endpoints 
|join (dataset = endpoints 
| alter CloudAccount = json_extract_scalar(cloud_info , "$.project_id")
    |fields endpoint_name, domain, platform, cloud_id, CloudAccount 
    ) as hi_a hi_a.endpoint_name = endpoint_name 
|arrayexpand cves 
|join (dataset=va_cves 
|fields affected_products, name) as cve_va cve_va.name = cves
```


With the cloudaccounts as parameter, search for "034777327369"
```
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


```
dataset = va_cves
| arrayexpand affected_hosts
| arrayexpand affected_products 
| join type = left (preset = host_inventory | fields endpoint_name, manufacturer, model) as host_inv affected_hosts = host_inv.endpoint_name 
| fields endpoint_name, name, affected_products, severity_score, impact_score
| sort desc impact_score 
```
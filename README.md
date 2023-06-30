# IOCs to CrowdStrike query
Short python tool that converts an excel file, csv file or json file (in STIX2 format) with IOCs to a simple Crowdstrike query.

You can run this tool with:
```sh
python3 quick-cs-query.py [-h] -f [FILE] -o [OUTPUT]
```

where:

| Options                    | Description                                  | Mandatory                         |
| -------------------------- | -------------------------------------------- | --------------------------------- |
| `-h`                       | Show help message and exit                   | No                                |
| `-f <input-file>.xlsx`     | Excel file with IOCs                         | No, uses "Book1.xlsx" as default  |
| `-o <output-file>.txt`     | Output file with query                       | No, uses "cs_query.txt" as default|


## Input format
The excel and csv file must include at least two collums **with** headers.
* The first collumn must have the IOC **type**
* The second collumn must have the IOC **value**

Example:
| Type       | Value                     |
| -----------| --------------------------|
| ipv4       | some-ip                   |
| domain     | some-domain               |
| SHA256     | some-hash                 |
| filename   | some-filename             |
| filepath   | some-filepath             |
| url        | some-url                  |


## Limitations
* This tool should be used as in a best/quick-effort to bulk query Crowdstrike with a very simple (not optimized) query.

* It considers IOCs of the type:
    * SHA256
    * IPv4
    * Single filenames
    * Single directories
    * Domains
    * URLs
*Note*: URLs are converted into their DNS since Crowdstrike doesn't track each URL that is visited (it's not a firewall).

* Ignores non-standard values.

* The CSV file should go under the operation "Text-to-collum" for the separator to become ';'. (this will be optimized in the future)

* No special validation of the final query is done, always double-check!

* For feature requests, support or bug reports, contact me directly.



Happy hunting 🕵️‍♀️


# Changelog
* 2023-06-30
    * [new] handle whitespaces in filenames and directories
    * [fix] fix duplicated domains after URL conversion
    * [new] validate SHA256
* 2023-06-29
    * [new] read json files in STIX2 format
    * [new] read csv files (converts to xlsx, reads it as normal, and deletes it)
    * [new] takes in URLs and converts them to their respective domains
* 2023-06-21
    * version 1

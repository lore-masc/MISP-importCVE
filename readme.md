# MISP Import CVE

The script allows to import all CVE list in MISP platform with its relative content like descriptions and references. MISP events are very useful thanks to the tags created for each platform subject to the described vulnerability.

### Prerequisites

Before install the script, you make sure to have permission to lo into virtual machine server that hosts the MISP application and to have role permission to get pyMISP API.

```
Authorization: a4PLf8QICdDdOmFjwdtSYqkCqn9CvN0VQt7mpUUf
```

### Installing

Placed in any folder on the server and types the following terminal commands.

Install pyMISP library in python3.

```
pip3 install pymisp
```

Clone this git repo and execute the script.

```
git clone https://github.com/lore-masc/MISP-importCVE.git
./update_cve.py
```

## Invoke a modality

* **Standard mode** - you can download all the zip provided by the NVD platform. The zip will be stored in the "nvd/" dir and extracted.
```
./update_cve.py
```
* **Local mode** - the script does not make any download, but simply extracts the zip files already present in the "nvd/" dir.
```
./update_cve.py l
./update_cve.py l CVE-2017
./update_cve.py l CVE-2017-0001
```
* **Update mode** - you can download the zip of the recent CVEs in the "nvd_recent/" dir and then import them.
$
```
./update_cve.py u
./update_cve.py u CVE-2017
./update_cve.py u CVE-2017-0001
```

## Authors

* **Lorenzo Masciullo** - *Initial work* - [lore-masc](https://github.com/lore-masc)

## License

This project is open source. Please, contact me for suggestions and reviews.


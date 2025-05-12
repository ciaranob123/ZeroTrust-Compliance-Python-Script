## Zero Trust Compliance Automation Framework

A Python-based Zero Trust compliance framework developed by **Ciaran O'Brien** for a Master's thesis in **Cybersecurity** at **Munster Technological University**.  
This tool automates compliance assessments across hybrid environments — including **on-premises ESXi infrastructure** and **Microsoft Azure** — with over 27 controls aligned to Zero Trust Architecture (ZTA) principles.


## Project Purpose

This framework was created to support small and medium-sized enterprises (SMEs) in:
- **Auditing Zero Trust compliance**
- **Generating automated security reports**
- **Reducing manual effort** in securing hybrid cloud deployments



---

## Features

-  Connects to ESXi hosts using **pyVmomi** and **Paramiko**
-  Queries Azure configurations via **Azure CLI**
-  Assesses compliance with **Zero Trust principles** (least privilege, segmentation, encryption, etc.)
-  Produces a **scored compliance report**
-  Generates a **PDF report** summarizing findings
-  Extensible: Easily add or modify checks

---

##  Technologies Used

- Python 3.10+
- Azure CLI
- pyVmomi
- Paramiko
- pdfkit + wkhtmltopdf
- CSV and JSON for input/output handling

---

##  Sample output

A sample output can be seen in the atatched PDF file




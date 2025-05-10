# LFSonar
Implementation code of Unveiling Security Vulnerabilities in Git Large File Storage Protocol

To cite this paper:

```
@INPROCEEDINGS {lfssecurity,
author = { Chen, Yuan and Wang, Qinying and Yang, Yong and Chen, Yuanchao and Li, Yuwei and Ji, Shouling },
booktitle = { 2025 IEEE Symposium on Security and Privacy (SP) },
title = {{ Unveiling Security Vulnerabilities in Git Large File Storage Protocol }},
year = {2025},
volume = {},
ISSN = {2375-1207},
pages = {431-448},
abstract = { As an extension to the Git version control system that optimizes the handling of large files and binary content, Git Large File Storage (LFS) has been widely adopted by nearly all Git platforms. While Git LFS offers significant improvements in managing large files, it introduces new security implications that remain largely unexplored. This paper presents the first comprehensive security analysis of Git LFS, identifying 11 critical security properties that LFS servers must uphold. Building on our analysis of these property violations, we propose four new attack vectors: Private LFS File Leakage, LFS File Replacement, Quota-based Denial of Service (DoS), and Quota Escape. These attacks exploit weaknesses in practical LFS server implementations and can lead to serious consequences, including unauthorized access to sensitive files, malware injection, denial of service affecting all public repositories, and resource abuse. To evaluate the security of LFS implementations, we develop a semi-automated black-box testing tool and apply it to 14 major Git platforms. We uncover 36 previously unknown vulnerabilities and have responsibly disclosed them to the respective platform maintainers, receiving positive feedback and over $1800 in bug bounty rewards. },
keywords = {},
doi = {10.1109/SP61157.2025.00123},
url = {https://doi.ieeecomputersociety.org/10.1109/SP61157.2025.00123},
publisher = {IEEE Computer Society},
address = {Los Alamitos, CA, USA},
month =May}
```

## About the code

To minimize the risk of this project being misused as an attack tool, only the core logic is open-sourced here. You are required to manually execute each test and interpret the results yourself.

## Run example: GitLab

```python
from core import *
# create two repos using two accounts, then create the fork repo
# REPO = "zjuchenyuan/lfstest.git"
# OTHERREPO = "zjuchenyuan2/otherrepo.git"
# FORKREPO = "zjuchenyuan/fork.git"

x = RunTest("gitlab.com",  REPO)
x.test2_upload_process()
#https://gitlab.com/zjuchenyuan/lfstest.git/gitlab-lfs/objects/2c045045273c6026c2d2653a5919d4ae9d3a91c165b79c808eaf0584b04893f3/1048576
#sha256 = "af333c61e89f50df7acf5de3a6c11ca2b5abb125ca746074d94f4afd865f4c56"

# so the url can be predicted, we enable overrideurl now:

x = RunTest("gitlab.com",  FORKREPO, verifydownload=True, overrideurl={
    "upload":"https://{sshtarget}/{repo}/gitlab-lfs/objects/{sha256}/{size}", 
    "download":"https://{sshtarget}/{repo}/gitlab-lfs/objects/{sha256}"
})
x.test2_upload_process()
# check the LFS quota usage

#x.test3_download_process(sha256)
#x.test3_download_process(sha256, key="deployread")
#https://gitlab.com/zjuchenyuan/lfstest.git/gitlab-lfs/objects/2c045045273c6026c2d2653a5919d4ae9d3a91c165b79c808eaf0584b04893f3

#private repo
#x.test4_otheruser_read(sha256) #ERROR: The project you were looking for could not be found or you don't have permission to view it.
#x.test5_otheruser_upload() #ERROR: The project you were looking for could not be found or you don't have permission to view it.
#x.test6_otheruser_upload_usedownloadtoken()  #-
#x.test16_download_use_otherusertoken(OTHERREPO, sha256) #HTTP Basic: Access denied. The provided password or token is incorrect or your account has 2FA enabl

#public repo
#x.test4_otheruser_read(sha256, "download") #ok
#x.test3_download_process(sha256, key="anonymous") #ok
#x.test5_otheruser_upload() #ERROR: You are not allowed to push code to this project.
#x.test6_otheruser_upload_usedownloadtoken() #Access forbidden. Check your access level.
#sha256 = x.test15_upload_use_otherusertoken(OTHERREPO) #401 HTTP Basic: Access denied. The provided password or token is incorrect or your account has 2FA enabled and you must use a personal access token instead of a password. See https://gitlab.com/help/topics/git/troubleshooting_git#error-on-git-fetch-http-basic-access-denied     

#x.test8_candownload_use_uploadtoken(sha256) #ok
#x.test9_canupload_use_deployread() #ERROR: This deploy key does not have write access to this project.
#x.test10_canupload_use_deployread_usedownloadtoken() #403 Access forbidden. Check your access level.

#x.test11_putwrongcontent()  
#x.test12_putwrongsize_smaller(size=1024) #500 Internal Server Error
#x.test13_putwrongsize_bigger() #400 SHA256 or size mismatch

#x.overwrite_existing_file("af333c61e89f50df7acf5de3a6c11ca2b5abb125ca746074d94f4afd865f4c56", b'file replaced', 
#   url="https://gitlab.com/zjuchenyuan/lfstest.git/gitlab-lfs/objects/af333c61e89f50df7acf5de3a6c11ca2b5abb125ca746074d94f4afd865f4c56/13", 
#   headers={"Accept": "application/vnd.git-lfs"}) #SHA256 or size mismatch <Response [400]>

#set as Archive
#sha256 = x.test2_upload_process() #ERROR: You are not allowed to push code to this project.
```


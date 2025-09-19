**1-all_XR_pre_check_CLI.py**
This script runs the CLI commands for the MoP and analyses for anamolies
 
**2-all_XR_pre_check_python.py**
This script run the dummy scripts on the router as part of the pre checks. 
It runs dummy yes first, waits for 20 minutes and then runs dummy no
 
**3-7_3_6_python_post_checks.py**
This script runs all the steps after the last reload as part of the MoP for devices running 7.3.6 IOS-XR version or higher
 
**4-file_upload.py**
This script uploads the dummy scripts to the hard drive of the router
 
**5-version_uptime.py**
This script will provide version and uptime for a list of hostnames that are input
 
**6-interface_shutdown_list_generator.py**
This script provides a list of interfaces that are currently down and also provides a list of interfaces that need to be shutdown before WP3 remediation. 
This is mostly for PhyNet devices
 
**7-7-7_3_5_post_check_part_I.py**
**8-7_3_5_post_check_part_II.py**
These two scripts will run all post-health checks which are in the MoP for systems running IOS-XR version 7.3.5
 
**9-dataplane_archive_logging.py**
This script will give you details and file location of the last time dataplane monitor was run on a device. 
It will also tell you whether archive logging is configured on a device or not
 
**10-dynamic_command_collector.py**
This list will provide the output of commands entered for a list of devices
 
**11-inventory_optics_comparison.py**
Run this script after the installation is complete and the router is powered on for the first. 
This script will check for changes in optics to make sure everything is plugged into the right port. 
It will also report any changes in Serial Numbers for RP/LC/FC


**For routers running IOS-XR version 7.3.6 and above:**
```
+---------------------------------------------------------------------+
| 0. Check router harddisk for dummy scripts                          |
+-------------------------------+-------------------------------------+
                                |
                                v
                   +------------------------------+
                   | Dummy scripts exist?         |
                   +------------------------------+
                     | Yes              | No
                     v                  v
+--------------------------------+   +---------------------------+
| Continue to next step          |   | Run 4-file_upload.py      |
+--------------------------------+   +---------------------------+
                     |                  |
                     +---------+--------+
                               |
                               v
+---------------------------------------------------------------------+
| 1. Run 1-all_XR_pre_check_CLI.py                                    |
+---------------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------------+
| 2. Get baseline outputs for different commands                      |
+---------------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------------+
| 3. Run 2-all_XR_python_pre_check.py                                 |
+---------------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------------+
| 4. Review existing degraded links                                   |
+---------------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------------+
| 5. On-site team performs remediation/installation                   |
+---------------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------------+
| 6. Wait ~15 minutes after device boots for NSR/link sync            |
+---------------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------------+
| 7. Run 11-inventory_optics_comparison.py to compare optics/hardware |
+---------------------------------------------------------------------+
                               |
                               v
+-----------------------------+-------------------------------+
| Any links down?             |                               |
+-----------------------------+                               |
           | Yes                                              | No
           v                                                  v
+-----------------------------+               +------------------------------------+
| Troubleshoot optics         |               | 9. First reload, start 20 min timer|
| (return to step 7)          |               +------------------------------------+
+-----------------------------+                          |
                                                         v
                                +--------------------------------------+
                                | 10. After router/NSR/interfaces up,  |
                                |     run 1-all_XR_pre_check_CLI.py    |
                                +--------------------------------------+
                                                        |
                                                        v
                                +--------------------------------------+
                                | 11. Second reload, start 20 min timer|
                                +--------------------------------------+
                                                        |
                                                        v
                                +--------------------------------------+
                                | 12. Run 3-7_3_6_python_post_checks.py|
                                +--------------------------------------+
                                                        |
                                                        v
                             +------------------------------+---------------------+
                             | Any problems in post-checks? |                     |
                             +------------------------------+                     |
                                         | Yes               	                   | No
                                         v                     	                  v
                            +-----------------------------+       +---------------------------+
                            | Troubleshoot as needed      |       |        Process Complete!  |
                            | (return to step 12)         |       +---------------------------+
                            +-----------------------------+
```

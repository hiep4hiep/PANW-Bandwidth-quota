# PaloAltoNetworks limit bandwidth quota per IP, User, AD Group

Function:
1. When you run the script, it asks for Firewall IP, username and password to log in. You should use superuser admin or whatever credential with full XML API permission.
2. The script will run infinitely. For every 1 minutes, it will process below:
Get the bandwidth usage report from Firewall.
Check which IP(s) are exceed the quota (I set 20MB). Calculate aggregate bandwidth usage per user, per AD group and check for maximum quota.

3. For violated objects:
- Block violated IP only, block by DAG. (pan-quota1.py)
- Block violated User. Even if he uses 2 or 3 IPs, block them all by DAG (pan-quota2.py).
- Block violated AD Group based on aggregated traffic of group. Then the script will create a Security Rule named BlockQuota to block this group. (pan-quota3.py)
- For all 3 features in one, use pan-quota.py
 
4. After 15 minutes, these IP(s), Group(s) will be released. The script unregistered them from DAG and remove security rule. Then these IP(s)/User(s)/Group(s) can connect to internet again.


 

How to set up:
1. How to run the script:
- Install python3.x in your Mac. If you run it in linux (Ubuntu, Kali), just run (sudo apt-get update && sudo apt-get install python3.6 && sudo apt-get install python3-pip).
- Install lib in Mac or Linux (pip3 install requests)
- Run it in terminal: python3 pan-quota.py
- In each 1 minitue cycle, it will show in terminal information of bandwidth usage status, which IP(s)/User(s)/Group(s) are blocked, which IP(s)/User(s)/Group(s) are released.

2. How to set up the Firewall:

- We leverage the custom report (based on ACC). The advantage of this solution is we don’t need to have a syslog server to count for bytes. But the down side is ACC aggregate traffic every 15 minutes (e.g 9:00, 9:15, 9:30, 9:45, 10:00…). So if the IP(s) use all their quota before the 15 minutes cycle of ACC, we do not block it immediately. We will block right at the ACC aggregate data cycle.
- You need to create a custom report exactly as below. Name is Quota with Q uppercase. Selected columns in right order
	- Name: Quota
	- Sort by: bytes
	- Group by: none
	- Time frame: 15 minutes
	- Selected columns: Source address > Source user > Bytes

 
- Next, you create a DAG (again, be careful on name and tag)
	- Name: quota
	- Dynamic tag: 'quota'
 
- Put DAG in a rule to block whatever you want from this group:
	- DAG will be source address
	- Make security policy by your own

 
 
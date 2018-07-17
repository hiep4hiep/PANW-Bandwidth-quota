import requests
import datetime
import time

#** Function to Process API connect **
def convert_xml(file):
    with open(file,"r") as f:
        xml = f.read()
        xml = xml.replace('\n','').replace('>     <','><').replace('>          <','><').replace('>               <','><')
    return(xml)


def get_api_key(ip,username,password):
    url = "http://"+ip+"/api/?type=keygen&user="+username+"&password="+password
    response = requests.get(url)
    r = response.text
    r = r[42:-26]
    return(r)

#** Function to Policy update to Firewall **

def user_id_add_post(ip,key):
    url = "http://"+ip+"/api/?type=user-id&key="+key+'&cmd='+convert_xml('user-id.xml')
    response = requests.post(url)
    print(response.text)


def dynamic_group(ip,key,xml):
    url = "http://"+ip+"/api/?type=user-id&key="+key+'&cmd='+xml
    response = requests.post(url)
    return(response.text)


def block_group(ip,key,grouplist):
    for group in grouplist:
        url = "http://"+ip+"/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules&element=<entry name='BlockGroup'><to><member>L3-Untrust</member></to><from><member>L3-Trust</member></from><source><member>any</member></source><destination><member>any</member></destination><source-user><member>"+group+"</member></source-user><category><member>any</member></category><application><member>any</member></application><service><member>any</member></service><hip-profiles><member>any</member></hip-profiles><action>deny</action></entry>&key="+key
        #print(url)
        response = requests.post(url)

    url = "http://"+ip+"/api/?type=commit&cmd=<commit><force></force></commit>&key="+key
    reponse2 = requests.post(url)


def release_group(ip,key,grouplist):
    for group in grouplist:
        url = "http://"+ip+"/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='BlockGroup']/source-user&element=<member>"+group+"</member>&key="+key
        #print(url)
        response = requests.post(url)

    url = "http://"+ip+"/api/?type=commit&cmd=<commit><force></force></commit>&key="+key
    reponse2 = requests.post(url)


#** Function to Process Custom report **


def get_job_id(ip,key):
    url = "http://"+ip+"/api/?type=report&async=yes&reporttype=custom&reportname=Quota&key="+key
    response = requests.post(url)
    with open("job-id.txt", "w") as f:
        f.write(response.text)
    with open("job-id.txt", "r") as f:
        lines = f.readlines()
        l = lines[4]
    return(l[9:-7])


def download_report(ip,key,jobid):
    url = "http://"+ip+"/api/?type=report&action=get&job-id="+jobid+"&key="+key
    response = requests.post(url)
    with open("statistic.txt", "w") as f:
        f.write(response.text)


#** Function to Extract information from report **

def get_bytes(file,l):
    for (i, line) in enumerate(file):
        if i == l:
            return(line)


def extract_ip():
    db = {}
    with open("statistic.txt", "r") as f:
        for (i, line) in enumerate(f):
            if "<src>" in line:
                db[line[11:-7]] = i
    return(db)


def extract_ip_reverse():
    db = {}
    with open("statistic.txt", "r") as f:
        for (i, line) in enumerate(f):
            if "<src>" in line:
                db[i] = line[11:-7]
    return(db)

#Mapping IP to Bytes
def extract_bytes(db):
    with open("statistic.txt", "r") as f:
        dict2 = {}
        line = f.readlines()
        dictkey = list(db.keys())
        j = 0
        for i in db.values():
            dict2[dictkey[j]] = line[i + 3][13:-9]
            j += 1
        return(dict2)

#Mapping Bytes to IP
def extract_bytes_reverse(db):
    with open("statistic.txt", "r") as f:
        dict2 = {}
        line = f.readlines()
        dictvalue = list(db.values())
        j = 0
        for i in db.keys():
            dict2[line[i + 3][13:-9]] = dictvalue[j]
            j += 1
        return(dict2)


#Mapping IP to User
def extract_user(db):
    with open("statistic.txt", "r") as f:
        dict3 = {}
        line = f.readlines()
        dictkey = list(db.keys())
        j = 0
        for i in db.values():
            dict3[dictkey[j]] = line[i + 2][15:-11]
            j += 1
        return(dict3)


#Mapping User to Bytes format bytes -- user
def extract_user_bytes(userd,bytesd):
    userl = list(userd.values())
    bytesl = list(bytesd.values())
    dict4 = {}
    for i in range(0,len(userl)):
        dict4[bytesl[i]] = userl[i]
    return(dict4)


#** Function to Evaluate data from report **


def compare_bytes(db,b):
    bad = []
    for ip, byte in db.items():
        if int(byte) >= int(b) * 1000000:
            bad.append(ip)
    return(bad)


#** Function to Process per user data **

def sum_bytes_user(dict):
    value = list(dict.values())
    key = list(dict.keys())
    key_short = []
    dictsum = {}

    for item in value:
        if item not in key_short:
            key_short.append(item)
            dictsum[item] = int(0)

    for k, v in dictsum.items():
        for n, i in dict.items():
            if k == i:
                v = int(v) + int(n)
                dictsum[k] = v

    return(dictsum)


#** Function to Process per AD Group data **


def find_str(s, char):
    index = 0

    if char in s:
        c = char[0]
        for ch in s:
            if ch == c:
                if s[index:index+len(char)] == char:
                    return index

            index += 1

    return -1


def get_group(ip,key,aduser):
    url = "http://"+ip+"/api/?type=op&key="+key+"&cmd=<show><user><user-ids><match-user>"+aduser+"</match-user></user-ids></user></show>"
    print(url)
    response = requests.post(url)
    with open("adgroup.txt","w") as f:
        f.write(response.text)
    with open("adgroup.txt","r") as f:
        line = f.readlines()
        groupline = line[3]
    pos = find_str(groupline, " cn=")
    return(groupline[pos+1:-2])


def extract_bytes_group(userbyted):
    adgroup = {}
    #print(userbyted)
    if userbyted:
        for user,byte in userbyted.items():
            if user != "":
                adgroup[byte] = get_group(ipaddr,k,user)
    return(adgroup)


def sum_bytes_group(dict):
    value = list(dict.values())
    key = list(dict.keys())
    key_short = []
    dictsum = {}

    for item in value:
        if item not in key_short:
            key_short.append(item)
            dictsum[item] = int(0)

    for k, v in dictsum.items():
        for n, i in dict.items():
            if k == i:
                v = int(v) + int(n)
                dictsum[k] = v

    return(dictsum)

def sum_bytes_ip(dict):
    value = list(dict.values())
    key = list(dict.keys())
    key_short = []
    dictsum = {}

    for item in value:
        if item not in key_short:
            key_short.append(item)
            dictsum[item] = int(0)

    for k, v in dictsum.items():
        for n, i in dict.items():
            if k == i:
                v = int(v) + int(n)
                dictsum[k] = v

    return(dictsum)

#** Function to Register DAG for violated IP, User **


def create_body_xml(l):
    xml_body_full = ""
    for ip in l:
        xml_body = '''\
                    <entry ip="{}">
                    <tag>
                    <member>quota</member>
                    </tag>
                    </entry>'''
        xml_body_full = xml_body_full + xml_body.format(ip)
    return(xml_body_full)


def register_dag_xml(l):
    xml_head = '''\
    <uid-message>
    <version>1.0</version>
    <type>update</type>
    <payload>
    <register>'''
    xml_tail = '''\
    </register> 
    </payload>
    </uid-message>'''
    xml = xml_head + create_body_xml(l) + xml_tail
    return(xml.replace('>    <', '><').replace('>                    <','><').replace('>     <','><').replace('    ',''))


def register_tag(l, ip, key):
    registerxml = register_dag_xml(l)
    dynamic_group(ip, key,registerxml)


def unregister_dag_xml(l):
    xml_head = '''\
    <uid-message>
    <version>1.0</version>
    <type>update</type>
    <payload>
    <unregister>'''
    xml_tail = '''\
    </unregister> 
    </payload>
    </uid-message>'''
    xml = xml_head + create_body_xml(l) + xml_tail
    return(xml.replace('\n', '').replace('>    <', '><').replace('>                    <','><').replace('>     <','><').replace('    ',''))


def unregister_tag(l, ip, key):
    unregisterxml = unregister_dag_xml(l).replace('\n','').replace('>    <','><').replace('>                    <','><').replace('>     <','><').replace('    ','')
    dynamic_group(ip, key, unregisterxml)


## >>> START <<< ##

#** Input information to log in to Firewall **
ipaddr = input("Firewall IP address: ")
user = input("Username: ")
passwd = input("Password: ")
bytesize = input("Limit threshold (MB):")
k = get_api_key(ipaddr,user,passwd)


#######################

starttime=time.time()
log = {}
loggroup = {}
count = 1
release_list = []

#** Main Program loop **


while True:
    print("\n\nCHECKING ROUND #",count, ":\n")
    count += 1
    print("Start time:",datetime.datetime.now().time())
    job_id = get_job_id(ipaddr,k)
    download_report(ipaddr,k,job_id)

    #Prepare database to process
    dictip = extract_ip()
    dictipreverse = extract_ip_reverse()
    dictbyte = extract_bytes_reverse(dictipreverse)#Map Bytes - IP
    dictipbytesum = sum_bytes_ip(dictbyte)#>>> Map IP - Sum of Bytes


    dictuser = extract_user(dictip)  #Map IP - Users
    dictuserbyte = extract_user_bytes(dictuser, dictipbytesum)
    dictusersum = sum_bytes_user(dictuserbyte) #>>> Map User - Sum of Bytes


    dictbytegroup = extract_bytes_group(dictusersum)
    dictbytegroupsum = sum_bytes_group(dictbytegroup) #>>> Map Group - Sum of Bytes

    # Begin process data
    print("Usage status by AD Group: ", dictbytegroupsum)
    violategroup = list(compare_bytes(dictbytegroupsum,bytesize))
    print("Usage status by User: ", dictusersum)
    violateuser = list(compare_bytes(dictusersum,bytesize))
    print("Usage status by IP: ",dictipbytesum)
    violateip = list(compare_bytes(dictipbytesum,bytesize))


    #Process to Block by Group
    if len(violategroup) != 0:
        block_group(ipaddr,k,violategroup)
        print("Violated Group:", violategroup)
        for badgroup in violategroup:
            if badgroup not in loggroup.keys():
                t = datetime.datetime.now()
                loggroup[badgroup] = t

    #Process to Block by User
    if len(violateuser) != 0:
        if '' not in violateuser:
            print("Violated User:",violateuser)
            listadd = []
            for baduser in violateuser:
                for add, usr in dictuser.items():
                    if baduser == usr:
                        if add not in violateip:
                            listadd.append(add)
                            violateip.append(add)
            #print(listadd)
            register_tag(listadd, ipaddr, k)

    #Process to Block by IP
    if len(violateip) != 0:
        register_tag(violateip,ipaddr,k)
        print("Violated IP:",violateip)
        for badip in violateip:
            if badip not in log.keys():
                t = datetime.datetime.now()
                log[badip] = t
        violate = []


    #Process to Release IP
    if bool(log) == True:
        release_list = []
        for ip,ti in log.items():
            if ti <= (datetime.datetime.now() - datetime.timedelta(minutes=15)):
                release_list.append(ip)
                unregister_tag(release_list, ipaddr, k)
                print("Released IP:",ip)
        if len(release_list) != 0:
            log = {}

    #Process to Release Group
    if bool(loggroup) == True:
        release_list_group = []
        for ipg,tig in loggroup.items():
            if tig <= (datetime.datetime.now() - datetime.timedelta(minutes=15)):
                release_list_group.append(ipg)
                release_group(ipaddr, k, release_list_group)
                print("Released Group:",ipg)
        if len(release_list_group) != 0:
            loggroup = {}

    print("Currently blocked IP list: ", log)
    print("Currently blocked group ", loggroup)

    time.sleep(60.0 - (time.time() % 60.0))



import requests
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


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


def get_config(ip,key):
    url ="http://"+ip+"/api/?type=config&action=get&xpath=/config/devices&key="+key
    response = requests.get(url)
    print(response.text)


def user_id_add_post(ip,key):
    url = "http://"+ip+"/api/?type=user-id&key="+key+'&cmd='+convert_xml('user-id.xml')
    response = requests.post(url)
    print(response.text)


def dynamic_group(ip,key):
    url = "http://"+ip+"/api/?type=user-id&key="+key+'&cmd='+convert_xml('dag.xml')
    response = requests.post(url)
    print(response.text)


def get_client_cert(ip,key):
    url = "http://"+ip+"/api/?type=op&key="+key+"&cmd=<show><sslmgr-store><config-certificate-info></config-certificate-info></sslmgr-store></show>"
    response = requests.post(url)
    return(response.text)


def print_selected_line(file,l):
    for (i, line) in enumerate(file):
        if i == l:
            return(line)


ipaddr = input("Firewall IP address: ")
user = input("Username: ")
passwd = input("Password: ")
k = get_api_key(ipaddr,user,passwd)
infor = get_client_cert(ipaddr,k)
with open("cert-status.txt","w") as f:
    f.write(infor)


def find_cert(i):
    with open("cert-status.txt", "r") as f:
        return(print_selected_line(f,i))


def create_content(seq,user,expiredate):
    html = """<p><span style="color: #0000ff;">Certificate {}:</span></p>
            <p>- User: {}</p>
            <p>- Expiration date: {}</p>
            """
    return(html.format(seq,user,expiredate))


def find_date():
    j = 1
    body = ""
    with open("cert-status.txt", "r") as f:
        for (i, line) in enumerate(f):
            if "db-exp-date" in line:
                month = line[-26:-23]
                year = line[-10:-5]
                if month == 'Jan':
                    m = 1
                if month == 'Feb':
                    m = 2
                if month == 'Mar':
                    m = 3
                if month == 'Apr':
                    m = 4
                if month == 'May':
                    m = 5
                if month == 'Jun':
                    m = 6
                if month == 'Jul':
                    m = 7
                if month == 'Aug':
                    m = 8
                if month == 'Sep':
                    m = 9
                if month == 'Oct':
                    m = 10
                if month == 'Nov':
                    m = 11
                if month == 'Dec':
                    m = 12
                if datetime.now().month - m <= 2 and int(year) <= datetime.now().year:
                    body = body + create_content(j,find_cert(i+4)[21:-1],find_cert(i)[35:-2])
                    j += 1
        return(body)

############## GUI EMAIL CANH BAO ##############


fromaddr = "hieptestlab@gmail.com"
toaddr = str(input("Receipent email: "))
msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = "[Firewall] Certificate expiration notification!"

html_head = """\
    <html>
      <head></head>
      <body>
        <p><span style="color: #ff0000;"><strong>Certificate expiration notification:</strong></span></p>"""
html_tail = """\
      </body>
    </html>
"""

body = html_head + find_date() + html_tail
print("Sending notification email to ",toaddr)
msg.attach(MIMEText(body,'html'))

server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login(fromaddr, "C1sco12345")
text = msg.as_string()
server.sendmail(fromaddr, toaddr, text)
server.quit()




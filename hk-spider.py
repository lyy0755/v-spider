from bs4 import BeautifulSoup
import requests
import re
import datetime
from email.mime.text import MIMEText
from email.header import Header
from smtplib import SMTP_SSL
import traceback
from lxml import html

def email(msg,title):
    #qq邮箱smtp服务器
    host_server = 'smtp.qq.com'
    #sender_qq为发件人的qq号码
    sender_qq = 'xxxx@qq.com'
    #pwd为qq邮箱的授权码
    pwd = 'xxxx'
    #发件人的邮箱
    sender_qq_mail = 'xxxx@qq.com'
    #收件人邮箱
    receiver = ['xxxxxx@qq.com']
    #邮件的正文内容

    mail_content = msg
    #邮件标题
    day = datetime.date.today()
    mail_title = str(day) + " : " + title
    #ssl登录
    try:
        smtp = SMTP_SSL(host_server)
        #set_debuglevel()是用来调试的。参数值为1表示开启调试模式，参数值为0关闭调试模式
        smtp.set_debuglevel(0)
        smtp.ehlo(host_server)
        smtp.login(sender_qq, pwd)

        msg = MIMEText(mail_content, "html", 'utf-8')
        msg["Subject"] = Header(mail_title, 'utf-8')
        msg["From"] = sender_qq_mail
        msg["To"] = ';'.join(receiver)
        smtp.sendmail(sender_qq_mail, receiver, msg.as_string())
        smtp.quit()
        print (title + " - " + url + " - 邮件发送成功")
    except Exception:
        print (title + " - " + url + " - Error: 无法发送邮件")
def hkinfo(url):
    descriptionlist=[]
    impactlist=[]
    solutionslist=[]
    affectedlist=[]
    videntifierlist=[]
    rlinkslist=[]
    # url="https://www.hkcert.org/my_url/en/alert/19051505"
    hkinfo_info = requests.get(url)
    hkinfo_response = hkinfo_info.text
    hkinfo_soup = BeautifulSoup(hkinfo_response, 'lxml')
    # 标题
    titles = str(hkinfo_soup.find_all('h1')[0].string)
    # 描述
    description = hkinfo_soup.find_all('div',id="content2")
    for d in description:
        descriptionlist.append(str(d).replace('display: none;', ''))
    description_info="<strong>Description</strong><br>"+"<br>".join(descriptionlist)+"<br><br>"
    # print(description_info)

    # 风险影响   
    impact = hkinfo_soup.find_all('div',id="content3")
    for i in impact:
        impactlist.append(str(i).replace('display: none;', ''))
    impact_info="<strong>impact</strong><br>"+"<br>".join(impactlist)+"<br><br>"
    # print(impact_info)

    # 影响版本
    affected = hkinfo_soup.find_all('div',id="content4")
    for a in affected:
        affectedlist.append(str(a).replace('display: none;', ''))
    affected_info="<strong>System / Technologies Affected</strong><br>"+"<br>".join(affectedlist)+"<br><br>"
    # print(affected_info)

    #解决办法
    solutions = hkinfo_soup.find_all('div',id="content5")
    for s in solutions:
        solutionslist.append(str(s).replace('display: none;', ''))
    solutions_info = "<strong>Solutions</strong><br>"+"<br>".join(solutionslist)+"<br><br>"
    # print(solutions_info)
    # 漏洞编号
    videntifier= hkinfo_soup.find_all('div',id="content6")
    for v in videntifier:
        videntifierlist.append(str(v).replace('display: none;', ''))
    videntifier_info="<strong>Vulnerability Identifier</strong><br>"+"<br>".join(videntifierlist)+"<br><br>"
    # print(videntifier_info)

    # 相关链接
    rlinks= hkinfo_soup.find_all('div',id="content8")
    for r in rlinks:
        rlinkslist.append(str(r).replace('display: none;', ''))
    rlinks_info = "<strong>Related Links</strong><br>"+"<br>".join(rlinkslist)+"<br><br>"
    # print(rlinks_info)
    msg = description_info + impact_info + affected_info + solutions_info + videntifier_info + rlinks_info
    email(msg,titles,url)

def hkcert():
    url="https://www.hkcert.org/"
    for num in range(1):
        hkurl = "https://www.hkcert.org/security-bulletin?p_p_id=3tech_list_security_bulletin_full_WAR_3tech_list_security_bulletin_fullportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-h3&p_p_col_count=1&_3tech_list_security_bulletin_full_WAR_3tech_list_security_bulletin_fullportlet_cur=" + \
            str(num) + "&_3tech_list_security_bulletin_full_WAR_3tech_list_security_bulletin_fullportlet_pageDelta=10&_3tech_list_security_bulletin_full_WAR_3tech_list_security_bulletin_fullportlet_year=0&_3tech_list_security_bulletin_full_WAR_3tech_list_security_bulletin_fullportlet_month=0&_3tech_list_security_bulletin_full_WAR_3tech_list_security_bulletin_fullportlet_last12months=Y&_3tech_list_security_bulletin_full_WAR_3tech_list_security_bulletin_fullportlet_struts.portlet.action=%2Fview%2Fview%2Findex&_3tech_list_security_bulletin_full_WAR_3tech_list_security_bulletin_fullportlet_struts.portlet.mode=view"
        hkinfos = requests.get(hkurl)
        response = hkinfos.text
        soup = BeautifulSoup(response, 'lxml')
        hktitle = soup.find_all('a', attrs={'id': re.compile("frm_sa_full_")})
        hktime = soup.find_all('span', attrs={'class': re.compile("date2")})
        for k, j in zip(hktitle, hktime):
            # 漏洞标题
            title = k.string
            # 漏洞日期
            time = j.string
            # 当天时间格式转换
            day = datetime.date.today().strftime('%Y / %m / %d')
            # 漏洞详情
            detailsurl = url+k.get('href')
            # 另外一种对比时间方法
            # day = datetime.date.today()
            # hktime = datetime.datetime.strptime(
            #     hktime, '%Y / %m / %d').date()

            # 找当天的漏洞发送邮件
            if time == day:
                createfile(detailsurl,title,time)
            else:
                print("旧漏洞: " + title +" - (" + time + ")" + " - " + detailsurl +' - 无需操作。' )

def createfile(detailsurl,title,time):
    # 获取日期，将日期做MD5作为文件名
    day = datetime.date.today().strftime('%Y / %m / %d')
    md5 = hashlib.md5()   
    md5.update(day.encode('utf-8'))
    filemd5 = md5.hexdigest()

    # 获取当前文件路径
    # detailsurl = 'https://www.hkcert.org/my_url/en/alert/19051505'
    dirpath = os.path.abspath(__file__)[:-12]

    filename = filemd5+".txt"
    file_path = dirpath + filename

    # 判断文件是否存在
    if os.path.isfile(filename):
        fr = open(file_path,"r")
        # 判断文件内容是否重复，重复不写入
        for i in fr.readlines():
            if detailsurl in i:
                print(detailsurl + ' - 已经发送过邮件。')
            else:
                fw = open(file_path,"a+")
                fw.writelines(str(detailsurl) + '\n')
                hkinfo(detailsurl)
        fr.closed
    else:
        print("file_path： "+ file_path)
        fw = open(file_path,"a+")
        fw.writelines(str(detailsurl) + '\n')
        hkinfo(detailsurl)
        fw.closed

if __name__ == "__main__":
    hkcert()
    # hkinfo()


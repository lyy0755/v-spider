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
    receiver = ['xxx@qq.com']
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
        print ("邮件发送成功")
    except Exception:
        print ("Error: 无法发送邮件")
def hkinfo():
    descriptionlist=[]
    impactlist=[]
    solutionslist=[]
    affectedlist=[]
    videntifierlist=[]
    rlinkslist=[]
    url="https://www.hkcert.org/my_url/en/alert/19051505"
    hkinfo_info = requests.get(url)
    hkinfo_response = hkinfo_info.text
    hkinfo_soup = BeautifulSoup(hkinfo_response, 'lxml')
    # 标题
    titles = str(hkinfo_soup.find_all('h1')[0].string)
    # 描述
    description = hkinfo_soup.find_all('div',id="content2")[0].find_all('p')
    if "<table" in str(hkinfo_soup.find_all('div',id="content2")[0]):
        table = str(hkinfo_soup.find_all('div',id="content2")[0].find_all('table')[0])
    else:
        table = ""

    for h in description:
        if h.string != "\xa0" and h.string != None:
            descriptionlist.append(h.string)
    description_info="<strong>Description</strong><br>"+"<br>".join(descriptionlist)+"<br>"+table+"<br><br>"
    # print(description_info)

    # 风险影响   
    impact = hkinfo_soup.find_all('div',id="content3")[0].find_all('li')
    for i in impact:
        if i.string != "\xa0" and i.string != None:
            impactlist.append(i.string)
    impact_info="<strong>impact</strong><br>"+"<br>".join(impactlist)+"<br><br>"
    # print(impact_info)

    # 影响版本
    affected = hkinfo_soup.find_all('div',id="content4")[0].find_all('li')
    for j in affected:
        if j.string != "\xa0" and j.string != None:
            affectedlist.append(j.string)
    affected_info="<strong>System / Technologies Affected</strong><br>"+"<br>".join(affectedlist)+"<br><br>"
    # print(affected_info)

    #解决办法
    solutions = hkinfo_soup.find_all('div',id="content5")[0]
    #解决办法-标题
    solutions_t = solutions.p.strong.text
    #解决办法-详情
    solutions_d = solutions.find_all('li')
    for n in solutions_d:
        if n.string != "\xa0" and n.string != None:
            solutionslist.append(n.string)
    solutions_info = "<strong>Solutions</strong><br>"+solutions_t+"<br>"+"<br>".join(solutionslist)+"<br><br>"

    # 漏洞编号
    videntifier= hkinfo_soup.find_all('div',id="content6")[0].find_all('a')
    for k in videntifier:
        astring = html.fromstring(str(k))
        if astring.xpath('//a/text()')[0]!=None:
            videntifierlist.append(astring.xpath('//a/text()')[0])
    videntifier_info="<strong>Vulnerability Identifier</strong><br>"+"<br>".join(videntifierlist)+"<br><br>"
    # print(videntifier_info)

    # 相关链接
    rlinks= hkinfo_soup.find_all('div',id="content8")[0].find_all('a')
    for l in rlinks:
            lstring = html.fromstring(str(l))
            if lstring.xpath('//a/text()')[0].strip() != None:
                rlinkslist.append(lstring.xpath('//a/text()')[0].strip())
    rlinks_info = "<strong>Related Links</strong><br>"+"<br>".join(rlinkslist)+"<br><br>"
    # print(rlinks_info)
    msg = description_info + impact_info + affected_info + solutions_info + videntifier_info + rlinks_info
    email(msg,titles)

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
                hkinfo(detailsurl)
                # print("title: "+title+"\n"+"time: "+str(time)+"\n"+"detial: "+detailsurl)


# def usinfo():
#     url='https://www.us-cert.gov/ncas/alerts/AA19-122A'
#     impactlist=[]
#     affectedlist=[]
#     videntifierlist=[]
#     rlinkslist=[]
#     usinfo_info = requests.get(url)
#     usinfo_response = usinfo_info.text
#     usinfo_soup = BeautifulSoup(usinfo_response, 'lxml')
#     # 标题
#     titles = str(usinfo_soup.find_all('h2')[0])
#     infos = usinfo_soup.find_all('div',class_="field-item even")
#     print(infos)
#     # 描述
#     description = infos[2].find_all('p')[0].text
#     description_info="<strong>Description</strong><br>"+description+"<br><br>"
#     # 风险影响  
#     impact = infos[3].find_all('p')[0].text
#     impact_info="<strong>impact</strong><br>"+impact+"<br><br>"
#     # 影响版本
#     affected = infos[0].find_all('p')[0].text
#     affected_info="<strong>System / Technologies Affected</strong><br>"+affected+"<br><br>"
#     # 解决办法
#     solutionslist = []
#     solutions = infos[4].find_all('p')
#     for m in solutions:
#         if m.string != "\xa0":
#             solutionslist.append(m.string)
#     solutions_info = "<strong>Solutions</strong><br>"+"<br>".join(solutionslist)+"<br><br>"

#     # 漏洞编号
#     videntifier = usinfo_soup.find_all('h1',id='page-title')[0].text
#     videntifier_info="<strong>Vulnerability Identifier</strong><br>"+videntifier+"<br><br>"

#     # 相关链接
#     rlinksist = []
#     rlinks = usinfo_soup.find_all('div',class_="field field-name-field-alert-references field-type-link-field field-label-hidden clearfix")[0].find_all('a')
#     for m in rlinks:
#         rlinkslist.append(m.get('href'))        
#     rlinks_info = "<strong>Related Links</strong><br>"+"<br>".join(rlinkslist)+"<br><br>"

#     msg = description_info + impact_info + affected_info + solutions_info + videntifier_info + rlinks_info
#     # email(msg,titles,url)

# def uscert():
#     url="https://www.us-cert.gov/"
#     for num in range(1):
#         usurl="https://www.us-cert.gov/ncas/alerts?page="+str(num)
#         usinfos = requests.get(usurl)
#         response = usinfos.text
#         soup = BeautifulSoup(response, 'lxml')
#         # 漏洞标题
#         ustitle = soup.find_all('a',attrs={'href': re.compile("/ncas/alerts/.+[A-Z]")})
#         # print(ustitle)
#         for i in ustitle:
#             # 漏洞标题
#             title=i.string
#             # 漏洞详情
#             detailsurl = url+i.get('href')
#             usinfo = requests.get(detailsurl)
#             response = usinfo.text
#             soup = BeautifulSoup(response, 'lxml')
#             # ustime=soup.footer.contents[0].split(':')
#             ustime=soup.footer.contents[0]
#             ustime=re.findall(": (.+ \\d\\d, 20\\d\\d)", ustime)[0]
#             # 漏洞日期
#             time = datetime.datetime.strptime(str(ustime), '%B %d, %Y').strftime('%Y / %m / %d')
#             day = datetime.date.today().strftime('%Y / %m / %d')
#             if time == day:
#                 usinfo(detailsurl)
#                 print("title: "+title+"\n"+"time: "+str(time)+"\n"+"detial: "+detailsurl)


if __name__ == "__main__":
    # hkcert()
    # uscert()
    # hkinfo()
    # usinfo()
    # email()
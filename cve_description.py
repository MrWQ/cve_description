# -*- coding: utf-8 -*-
# @Time : 2022/7/6 13:46
# @Author : ordar
# @Project : cve_description
# @File : cve_description.py
# @Python: 3.7.5
import requests
import datetime
import re
import json

# 黑名单，防止github数据污染
black_list = []
with open("blick_list.txt", "r", encoding="utf8") as bf:
    temp = bf.readlines()
    for i in temp:
        black_list.append(i.strip())


search_url = "https://raw.githubusercontent.com/ycdxsb/PocOrExp_in_Github/main/PocOrExp.md"
cdn_search_url = "https://cdn.jsdelivr.net/gh/ycdxsb/PocOrExp_in_Github@main/PocOrExp.md"

resp = requests.get(search_url)
pre_html = resp.text

# 规范格式
pre_html = pre_html.replace("\n\n\n", "\n")
pre_html = pre_html.replace("\n##", "\n\n##")
# print(pre_html)

# 去掉年份
today_year = int(datetime.datetime.now().year)
# next_year = today_year + 1
for i in range(1999, today_year):
    pre_html = pre_html.replace("\n## {}\n".format(str(i)), "")
# pre_html = pre_html.replace("## {}\n".format(str(today_year)), "")
pre_html_list = pre_html.split('\n\n##')
print(pre_html_list)

# 生成字典
results = []
for i in pre_html_list:
    i = i.replace("\n", "<br>").strip()
    p = re.findall(r'^(CVE-\d+-\d+)<br>(.*?)<br><br>- (.*?)$', i)

    if p:
        p_item = p[0]
        item = {}
        item["cve_code"] = p_item[0]
        item["description"] = str(p_item[1]).strip()
        temp = p_item[2]
        pocs = re.findall(r'\[(http.*?)\]\(.*?\)', temp)
        item["poc"] = pocs
        results.append(item)

# 写入文件
with open("cve_description_poc.json", 'w', encoding='utf8') as f:
    f.write(json.dumps(results, indent=2))

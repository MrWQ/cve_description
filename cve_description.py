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
next_year = today_year + 1
for i in range(1999, next_year):
    pre_html = pre_html.replace("\n## {}\n".format(str(i)), "")

# 规范格式
html = pre_html.replace("\n-", "-")
html = html.replace(".\n", ".\n\n")
html = html.replace("\n-", "-")
html = html + "\n"
# print(html)

# 提取数据
pre_results = re.findall(r"## (CVE-\d+-\d+)\n(.*?)\n(.*?)\n\n", html)
# print(pre_results)

# 生成字典
results = []
for i in pre_results:
    item = {}
    item["cve_code"] = i[0]
    item["description"] = i[1]
    item["poc"] = []
    a = str(i[2]).replace("- ", "\n- ").strip() + "\n"
    temp_poc = re.findall(r'\[(.*?)\]', a)
    if temp_poc:
        for j in temp_poc:
            if "http" in j and j not in black_list:
                item["poc"].append(j)
                print(item)
    results.append(item)
for i in results:
    print(i)

# 写入文件
with open("cve_description_poc.json", 'w', encoding='utf8') as f:
    f.write(json.dumps(results, indent=2))

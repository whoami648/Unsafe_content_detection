import requests
import json
# -*- coding: utf-8 -*-
import csv
import requests
import os
import shutil
from tqdm import tqdm
'''
Descripttion: 用来针对代码的不健康内容做检测，目前主要有两种办法做检测，第一种可以调用百度账户的接口，第二种为目前采用数据库判断是否合格,异常可以放邮件,加自身的数据库
version: V1.0
Author: zyx
Date: 2024-07-25 10:21:25
LastEditors: zyx
LastEditTime: 2024-08-11 17:22:07
'''

    #     "details": [
save_dir = "" #需要爬取目标存储地址
data_set_path = r"Sensitive-lexicon/ThirdPartyCompatibleFormats/TrChat/SensitiveLexicon.json"
csv_path = r"results.csv"
sava_dir = "new_unhealthy_detection"
if not os.path.exists(sava_dir):
    os.mkdir(sava_dir)
'''{
    "scanId": 11,#目标编号
    "type": 4,#检测
    "result": []
}'''
with open(data_set_path, 'r', encoding='utf-8') as file:  
    # 使用json.load()方法解析JSON数据  
    data_set = json.load(file)["words"]  #数据库

def Unhealthy_content_detection_callbacks():
    #处理数据
    cnt = 0
    with open(csv_path,"r") as f:
        reader = csv.reader(f)
        for read in tqdm(reader):
            cnt+=1
            if read[0]=="repo.url":
                continue
            url = read[0]
            conResult = {"totalCount": 0,"details": []}
            try:
                directory = git_clone(url)
                ans = traverse_directory(directory,conResult)
                huidiao(str(ans),str(cnt),read[1],os.path.basename(url))
                
            except:
                continue
                

def find_word_position(text, word):
    '''lin,col'''
    lines = text.split('\n')
    for line_num, line in enumerate(lines, start=1):
        words = line.split()
        for col_num, w in enumerate(words, start=1):
            if word == w:
                return line_num, col_num
    return None, None

def huidiao(conResult,scanId,name):
    # http://222.20.126.217:8082/jyh/code/scan/resultCallBack
    # res = {
    #     "scanId": scanId,#目标编号"string
    #     "type": 4,#检测
    #     "result": result#"string"
    # }
    res = {
    "scanId": scanId,
    "type": 4,
    "checkCode": "4001",
    "conResult": conResult
}

    url = 'http://222.20.126.217:8082/jyh/code/scan/resultCallBack'
    headers = {'Content-Type': 'application/json;charset=UTF-8'}

    response = requests.post(url,json=res)#,headers=headers

    json_str = json.dumps(res,indent=4)

    with open(os.path.join(sava_dir,name+".json"),"w+",newline="") as json_f:
        json_f.write(json_str)

    if response.status_code == 200:
        print('数据发送成功！')
    else:
        print('数据发送失败...')
        with open("error.csv","a+",newline="") as f:
            writer = csv.writer(f)
            writer.writerow([url,"Failed to send data"])



def Code_detection_unhealthy(text,language,filename):
    #  '''
    #  "conResult": {
    #     "totalCount": 1,
    #     "details": [
    #         {
    #             "codeType": "Java",
    #             "filename": "example.java",
    #             "codeLine": 10,
    #             "codeColumn": 5,
    #             "warning": "file context unhealthy",
    #             "context": "String query = \"SELECT * FROM users WHERE name = '\" + userName + \"'\";"
    #       }
    #     ]
    # }
    # '''
    cnt = 0 #记录存在不健康内容的个数
    details = []
    ans =  {
            "codeType": "Java",
            "filename": "example.java",
            "codeLine": 10,
            "codeColumn": 5,
            "warning": "file context unhealthy",
            "context": "String query = \"SELECT * FROM users WHERE name = '\" + userName + \"'\";"
        }
    
    

    #词汇检测
    for word in data_set:
        lin,col = find_word_position(text, word)
        if lin:
            cnt+=1
            ans["codeType"] = language
            ans["codeColumn"] = language
            ans["filename"] = filename
            ans["codeColumn"] = col
            ans["codeLine"] = lin
            ans["context"] = f"{word} in {filename}"
            details.append(ans)

    
    return cnt,details
# 百度percision: 0.5952200303490136
def git_clone(url):

    package__name = url.split("/")[-1]
    save_dir1 = os.path.join(save_dir,package__name)
    if not os.path.exists(save_dir1):
        os.mkdir(save_dir1)
    try:
        print("git clone "+url+" "+save_dir1)
        response = os.system(
            "git clone "+url+" "+save_dir1
        )
    except:
        with open("error.csv","a+",newline="") as f:
            writer = csv.writer(f)
            writer.writerow([url,"git clone fail"])

        return "Error: git clone fail"
        
    
    return save_dir1

def Detection_language(folder_name):
    '''检测目标文件使用的编程语言'''
    if ".py" in folder_name.lower():
        return "Python"
    elif ".java" in folder_name.lower():
        return "Java"
    elif ".javascript" in folder_name.lower():
        return "JavaScript"
    elif ".cpp" in folder_name.lower():
        return "C++"
    elif ".go" in folder_name.lower():
        return "go"
    elif ".php" in folder_name.lower():
        return "PHP"
    elif ".c" in folder_name.lower():
        return "C"
    else:
        return "Unknown"
    
def Code_unhealthy_detection_baidu(text):
    # 百度
    # 获取access_token
    # client_id 为官网获取的AK， client_secret 为官网获取的SK

    client_id = API_KEY
    client_secret = SECRET_KEY


    token_url = "https://aip.baidubce.com/oauth/2.0/token"
    host = f"{token_url}?grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}"

    response = requests.get(host)
    access_token = response.json().get("access_token")


    request_url = "https://aip.baidubce.com/rest/2.0/solution/v1/text_censor/v2/user_defined"

    body = {
        "text": text,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    request_url = f"{request_url}?access_token={access_token}"

    response = requests.post(request_url, headers=headers, data=body)
    content = json.loads(response.content.decode("UTF-8"))

    return content

def traverse_directory(directory,conResult):
    '''
     "conResult": {
        "totalCount": 1,
        "details": [
            {
                "codeType": "Java",
                "filename": "example.java",
                "codeLine": 10,
                "codeColumn": 5,
                "warning": "file context unhealthy",
                "context": "String query = \"SELECT * FROM users WHERE name = '\" + userName + \"'\";"
          }
        ]
    }
    '''
    text = ""
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path,"r", encoding='latin-1') as f:# encoding 
                text=f.read()
                filename=os.path.basename(file_path)
                language = Detection_language(filename)
                cnt,details= Code_detection_unhealthy(text,language,filename)#代码内容检测
                conResult["totalCount"] += cnt
                conResult["details"] += details #汇总一个文件的

                
                    
    #shutil.rmtree(directory) 
    
    return conResult




if __name__=='__main__':
    #git_clone("https://github.com/KhronosGroup/Vulkan-ValidationLayers","save_dir")
    #traverse_directory("save_dir")
    # API_KEY = "JagfKxWUuUKYFMHn5DXLP8Du"
    # SECRET_KEY = "9zR0JMPLUm9SjOiwSEPC31YCFpclxVsi"
    #process_data()
    #nohup python huidiao.py > huidiao.log 2>&1 &
    Unhealthy_content_detection_callbacks()
    # file_path = r"Sensitive-lexicon\ThirdPartyCompatibleFormats\TrChat\SensitiveLexicon.json"
    # with open(file_path, 'r', encoding='utf-8') as file:
    #     data = json.load(file)
    # words = data['words']
    # length = len(words)
    # cnt = 0
    # for word in tqdm(words):
    #     if main(word)==2:
    #         cnt+=1
    # print("percision:",cnt/length)


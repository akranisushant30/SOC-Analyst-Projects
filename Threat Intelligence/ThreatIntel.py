import os
import re
import sys

# Patterns : show how data looks to system
IOC_patterns = {
    "IP" : r'\b(\d{1,3}\.){3}\d{1,3}\b', 
    "DOMAIN": r'\b[a-zA-z0-9.-]+\.[a-zA-z]{2,}\b',
    "HASH" : r'\b[a-fA-F0-9]{64}\b'
}

def clean_data(folder_path):
    all_found=[] #list to store data

    #LOAD & PARSE 
    for filename in os.listdir(folder_path):
        with open(os.path.join(folder_path,filename),'r') as f:
            content = f.read() #Read text from file
            for ioc_type,pattern in IOC_patterns.items():
                matches = re.findall(pattern,content) #Finding Match with regex
                for m in matches:
                    all_found.append({"val":m,"type":ioc_type,"src":filename})

    #correlate
    unique_data={}
    for item in all_found:
        val = item["val"]
        if val not in unique_data:
            #create new entry if found first time
            unique_data[val]={"type":item['type'],"count":1,"sources":[item['src']]}
        else:
            #if found again increase count 
            if item["src"] not in unique_data[val]["sources"]:
                unique_data[val]["count"] += 1
                unique_data[val]["sources"].append(item["src"])
    return unique_data

#Output
if __name__=="__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "feeds/"
    result = clean_data(path)

    #Table Header
    print(f"{'INDICATOR':<45} | {'TYPE':<10} | {'COUNT':<5} | {'RISK'}")
    print("_"*75)

    for ioc, info in result.items():
        risk = "HIGH" if info['count'] > 1 else 'LOW'
        print(f"{ioc:<45} | {info['type']:<10} | {info['count']:<5} | {risk}")

    #Create Blocklist file
    with open("blocklist.txt",'w') as f:
        for ioc,info in result.items():
            if info['count'] > 1:
                f.write(f"{ioc}\n")
    
    print("\n[!] Processing Complete. High-risk entries saved to blocklist.txt")
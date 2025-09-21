import pandas as pd
import random
import math
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import numpy as np
from scipy.optimize import minimize
import csv
import os 
import sys


# <mobility_model> <node_count> <group_size> <iter>
# <mobility_model> 
mobility_model = sys.argv[1]
# <node_count> 
node_count = int(sys.argv[2])
# <group_size> 
group_size = int(sys.argv[3])
# <traffic_model> "standard" or "event" or "test"
traffic_model = sys.argv[4]
# <iter> 
iter = int(sys.argv[5])


#treekem message count
treekem_count = 20
sum = 0

#traffic output file
filename = traffic_model+'/'+mobility_model+'/node'+str(node_count)+'/group'+str(group_size)+'/'+str(iter)+'.txt'
if not os.path.exists(traffic_model+'/'+mobility_model+'/node'+str(node_count)+'/group'+str(group_size)+'/'):
        # Create the directory
        os.makedirs(traffic_model+'/'+mobility_model+'/node'+str(node_count)+'/group'+str(group_size)+'/')

#groups output file
groups_filename = '../groups/'+traffic_model+'/'+mobility_model+'/node'+str(node_count)+'/group'+str(group_size)+'/'+str(iter)+'.txt'
if not os.path.exists('../groups/'+traffic_model+'/'+mobility_model+'/node'+str(node_count)+'/group'+str(group_size)+'/'):
        # Create the directory
        os.makedirs('../groups/'+traffic_model+'/'+mobility_model+'/node'+str(node_count)+'/group'+str(group_size)+'/')


#generate groups from position file
positions_full = np.load("../mobility_models/position_files/"+mobility_model+"/node"+str(node_count)+"/"+str(iter)+".npy")

seconds = positions_full.shape[0]
positions = positions_full[0]

isInGroup = np.zeros(positions.shape[0])
groups = []

nearby_fraction = .8
end_buffer = 60
message_interval = 60
send_interval = 1

def findSubarrayIndex(arrays, target):
    for index, subarray in enumerate(arrays):
        if target in subarray:
            return index
    return -1 

def getDistanceFromPoint(point1, point2):
    length = math.sqrt((float(point2[0]) - float(point1[0]))**2 + (float(point2[1]) - float(point1[1]))**2)
    return length

def findClosestNode(idx):
    closest_idx = 0
    distance = 9999999
    for node in range(len(positions)):
        if node == idx:
            continue
        if isInGroup[node] != 0:
            continue
        d = getDistanceFromPoint(positions[idx], positions[node])
        if d < distance:
            closest_idx = node
            distance = d
    return closest_idx

def getRandomNode():
    isUnmatched = False
    while isUnmatched == False:
        random_idx = random.randint(0,len(positions)-1)
        if (isInGroup[random_idx] == 0):
            return random_idx

groupIter = 0

for node in range(len(positions)):
    #if node is not already in group
    if(isInGroup[node] == 0):
        #form group around node
        zeros = np.count_nonzero(isInGroup == 0)
        #if more nodes than group size remaining
        if(zeros > group_size-1):
            group = []
            group.append(node)
            isInGroup[node] = 1
            # if enough to get outside percentage
            if (group_size*(1-nearby_fraction) > 1):
                for i in range(round(group_size*(1-nearby_fraction))):
                    random_node_idx = getRandomNode()
                    group.append(int(random_node_idx))
                    isInGroup[random_node_idx] = 1
            for i in range(round(group_size*nearby_fraction)-1):
                closest_node_idx = findClosestNode(node)
                #add 1 for idx
                isInGroup[closest_node_idx] = 1
                group.append(int(closest_node_idx))
            groups.append(group)
        else:
            toAdd = np.where(isInGroup == 0)[0]
            group = []
            if len(toAdd) <= 1:
                isInGroup[toAdd[0]] = 1
                groups[len(groups)-1].append(int(toAdd[0]))
            else:
                for t in toAdd:
                    isInGroup[t] = 1
                    group.append(t)
                groups.append(group)
        groupIter+=1   

header = ['messageID', 'messageSender', 'messageReceiver(s)', 'messageSendTime', 'messageTTL', 'messageText']

message_data = []

if traffic_model == "event":

    #metadata
    expireTime = 1000 
    textsize = 250
    time = math.floor(seconds-end_buffer)
    message_id = 1

    thresholdMaxDist= 1.5
    thresholdMinDist= -1.5

    sum=0

    for s in range(1,seconds):

        #event traffic
        treekem_count = np.random.poisson((node_count*.005), node_count)
        for node in range(node_count):
            for i in range(treekem_count[node]):
                dist = math.sqrt((positions_full[s][node][0] - positions_full[s-1][node][0])**2 + (positions_full[s][node][1] - positions_full[s-1][node][1])**2)
                if((dist > thresholdMaxDist) or (dist < thresholdMinDist)):
                    message_sender = node
                    message_recipients = []
                    for sublist in groups:
                        # Check if the value is in the sublist
                        if message_sender in sublist:
                            for s in sublist:
                                if s != node:
                                    message_recipients.append(s)
                            break 
                    message_sendtime = s + random.uniform(0, send_interval)
                    message_ttl = message_sendtime + expireTime
                    message_textsize = textsize
                    message_data.append([message_id, message_sender, message_recipients, message_sendtime, message_ttl, message_textsize])
                    message_id +=1

        #background messages
        expireTime = 1000 
        textsize = 250
        time_iters = math.floor((seconds-end_buffer)/message_interval)
        treekem_count = np.random.poisson((1/(node_count * (time_iters/2))), node_count)
        for node in range(node_count):
            if(treekem_count[node] > 0):
                message_sender = node
                message_recipients = []
                for sublist in groups:
                    # Check if the value is in the sublist
                    if message_sender in sublist:
                        for s in sublist:
                            if s != node:
                                message_recipients.append(s)
                        break 
                message_sendtime = s + random.uniform(0, send_interval)
                message_ttl = message_sendtime + expireTime
                message_textsize = textsize
                message_data.append([message_id, message_sender, message_recipients, message_sendtime, message_ttl, message_textsize])
                message_id +=1
    
    #treekem messages

    for iter_count in range(treekem_count):
        message_sender = random.randint(0, node_count-1)
        message_recipients = []
        for sublist in groups:
            # Check if the value is in the sublist
            if message_sender in sublist:
                for s in sublist:
                    if s != node:
                        message_recipients.append(s)
                break 
        message_sendtime = random.uniform(0, 900)
        message_ttl = message_sendtime + expireTime
        message_textsize = textsize
        message_data.append([message_id, message_sender, message_recipients, message_sendtime, message_ttl, message_textsize])
        message_id +=1
    time +=message_interval


elif traffic_model == "standard":
    
    expireTime = 1000 
    textsize = 250
    time_iters = math.floor((seconds-end_buffer)/message_interval)
    message_id = 1
    time = 0

    #standard traffic
    for s in range(time_iters):
        for node in range(node_count):
            message_sender = node
            message_recipients = []
            for sublist in groups:
                # Check if the value is in the sublist
                if message_sender in sublist:
                    for s in sublist:
                        if s != node:
                            message_recipients.append(s)
                    break 

            message_sendtime = time + random.uniform(0, message_interval)
            message_ttl = message_sendtime + expireTime
            message_textsize = textsize
            message_data.append([message_id, message_sender, message_recipients, message_sendtime, message_ttl, message_textsize])
            message_id +=1
        time +=message_interval
    
    #treekem messages

    for iter_count in range(treekem_count):
        message_sender = random.randint(0, node_count-1)
        message_recipients = []
        for sublist in groups:
            # Check if the value is in the sublist
            if message_sender in sublist:
                for s in sublist:
                    if s != node:
                        message_recipients.append(s)
                break 
        message_sendtime = random.uniform(0, 900)
        message_ttl = message_sendtime + expireTime
        message_textsize = textsize
        message_data.append([message_id, message_sender, message_recipients, message_sendtime, message_ttl, 1])
        message_id +=1
    time +=message_interval


all = [header] + message_data


with open(filename, 'w', newline='') as file:
    writer = csv.writer(file, delimiter='\t')
    writer.writerows(all)


with open(groups_filename, 'w') as file:
    for sub_array in groups:
        line = str(sub_array) + '\n'
        file.write(line)
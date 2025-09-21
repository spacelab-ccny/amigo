import pandas as pd
import random
import matplotlib.pyplot as plt
import math
import numpy as np
import matplotlib.animation as animation 
from matplotlib.animation import FFMpegWriter
import concurrent.futures
import os
import sys 

runtype = sys.argv[1]
nodecount = int(sys.argv[2])
iter = sys.argv[3]
seconds = int(sys.argv[4])

# -------------------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------------------
# BASIC FUNCTIONS
# -------------------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------------------

# -------------------------------------------------------------------------------------------------------------------------------
#   getDistanceFromPoint
# - given 2 x,y coordinates, find distance between them
# -------------------------------------------------------------------------------------------------------------------------------
def getDistanceFromPoint(point1, point2):
    length = math.sqrt((float(point2[0]) - float(point1[0]))**2 + (float(point2[1]) - float(point1[1]))**2)
    return length

# -------------------------------------------------------------------------------------------------------------------------------
#   getTwoRandomPoints
# - get two random points in the simulation space in the area defined by x,y
# - points must have a euclidean distance within endpoint range, or else, regenerate
# -------------------------------------------------------------------------------------------------------------------------------
def getTwoRandomPoints(x, y, endPointRange):
    fitCriteria = False
    while fitCriteria == False:
        randomPoint1 = (random.uniform(x[0], x[1]), random.uniform(y[0], y[1]))
        randomPoint2 = (random.uniform(x[0], x[1]), random.uniform(y[0], y[1]))
        if (getDistanceFromPoint(randomPoint1, randomPoint2) >= endPointRange[0]) and (getDistanceFromPoint(randomPoint1, randomPoint2) <= endPointRange[1]):
            fitCriteria = True
    return randomPoint1, randomPoint2

# -------------------------------------------------------------------------------------------------------------------------------
#   generateSubtleCurves
# - linear interpolation and small random adjustments to the control points
# -------------------------------------------------------------------------------------------------------------------------------
def generateSubtleCurves(start, end, num_points, num_curves, max_deviation):
    path = [start]
    for _ in range(num_curves):
        control_point = (
            random.uniform(start[0], end[0]),
            random.uniform(start[1], end[1])
        )  
        for t in range(1, num_points + 1):
            deviation_x = random.uniform(-max_deviation, max_deviation)
            deviation_y = random.uniform(-max_deviation, max_deviation)
            x = (1 - t / num_points) * start[0] + t / num_points * (control_point[0] + deviation_x)
            y = (1 - t / num_points) * start[1] + t / num_points * (control_point[1] + deviation_y)
            path.append((x, y))
    path.append((end[0],end[1]))
    return path

# -------------------------------------------------------------------------------------------------------------------------------
#   findSlope
# - given 2 points on line, finds line's slope
# -------------------------------------------------------------------------------------------------------------------------------
def findSlope(point1, point2):
    x1, y1 = point1
    x2, y2 = point2
    slope = (y2 - y1) / (x2 - x1)
    return slope

# -------------------------------------------------------------------------------------------------------------------------------
#   findIntercept
# - given 2 points on line, finds line's intercept
# -------------------------------------------------------------------------------------------------------------------------------
def findIntercept(point1, point2):
    x1, y1 = point1
    x2, y2 = point2
    slope = findSlope(point1, point2)
    # Calculate y-intercept (b) using either point
    intercept = y1 - slope * x1
    return intercept

# -------------------------------------------------------------------------------------------------------------------------------
#   distanceToLine
# - given point, slope, intercept of line, returns distance from point to line
# -------------------------------------------------------------------------------------------------------------------------------
def distanceToLine(x, y, m, b):
    # Calculate the distance from the point (x, y) to the line y = mx + b
    return abs(m*x - y + b) / math.sqrt(m**2 + 1)

# -------------------------------------------------------------------------------------------------------------------------------
#   findLineEquation
# - given 2 points, returns the equation of the line 
# -------------------------------------------------------------------------------------------------------------------------------
def findLineEquation(point1, point2):
    slope = findSlope(point1, point2)
    intercept = findIntercept(point1, point2)
    # Define the equation of the line
    def line_equation(x):
        return slope * x + intercept
    return line_equation

# -------------------------------------------------------------------------------------------------------------------------------
#   generatePointsAlongLines
# - given the lines, assign protesters to positions roughly along lines
# - plot the protester positions before noise is added
# -------------------------------------------------------------------------------------------------------------------------------
def generatePointsAlongLines(lines, depth, distanceApart):
    #get pro positions approx along lines & plot
    pathLines = []
    for lineIter in range(depth):
        path = assignToPath(lines[lineIter], depth, distanceApart)
        pathLines.append(path)
    return pathLines

# -------------------------------------------------------------------------------------------------------------------------------
#   getRandomWithin
# - get random point within the x,y plane provided
# -------------------------------------------------------------------------------------------------------------------------------
def getRandomWithin(x1,x2,y1,y2):
    random_x = random.uniform(min(x1, x2), max(x1, x2))
    random_y = random.uniform(min(y1, y2), max(y1, y2))
    return random_x, random_y

# -------------------------------------------------------------------------------------------------------------------------------
#   calculatePointBetween
# - gets the point equidistant between two points
# -------------------------------------------------------------------------------------------------------------------------------
def calculatePointBetween(point1, point2, dist):
    totalDist = math.sqrt((point2[0] - point1[0]) ** 2 + (point2[1] - point1[1]) ** 2)
    ratio = dist / totalDist
    x = point1[0] + ratio * (point2[0] - point1[0])
    y = point1[1] + ratio * (point2[1] - point1[1])
    return [x, y]

# -------------------------------------------------------------------------------------------------------------------------------
#   generatePointsBetween
# - gets multiple points (as parameterized by numPoints) equidistant between points 1 and 2, and returns an array of points
# -------------------------------------------------------------------------------------------------------------------------------
def generatePointsBetween(point1, point2, numPoints):
    points = []
    totalDist = math.sqrt((point2[0] - point1[0]) ** 2 + (point2[1] - point1[1]) ** 2)
    for i in range(numPoints + 1):
        dist = i * totalDist / numPoints
        newPoint = calculatePointBetween(point1, point2, dist)
        points.append(newPoint)
    return points

# -------------------------------------------------------------------------------------------------------------------------------
#   getParallelLines
# - given an initial line (which goes through x1,y1, x2,y2), returns 2 parallel lines that are <distance> length away 
# -------------------------------------------------------------------------------------------------------------------------------
def getParallelLines(x1, y1, x2, y2, distance):
    # Calculate the direction vector of the original line
    directionVector = np.array([x2 - x1, y2 - y1])
    # Normalize the direction vector
    normalizedDirection = directionVector / np.linalg.norm(directionVector)
    # Calculate the perpendicular vector by swapping x and y components and negating one of them
    perpendicularVector = np.array([-normalizedDirection[1], normalizedDirection[0]])
    # Calculate the new endpoints for the first parallel line
    parallelLine1Start = np.array([x1, y1]) + distance * perpendicularVector
    parallelLine1End = np.array([x2, y2]) + distance * perpendicularVector
    # Calculate the new endpoints for the second parallel line on the opposite side
    parallelLine2Start = np.array([x1, y1]) - distance * perpendicularVector
    parallelLine2End = np.array([x2, y2]) - distance * perpendicularVector
    
    return [[parallelLine1Start, parallelLine1End], [parallelLine2Start, parallelLine2End]]

# -------------------------------------------------------------------------------------------------------------------------------
#   getRandomSpeed
# - get random speed within bounds provided
# - uses lognormal centered at logcenter value (i.e. weights speeds towards walking speed)
# -------------------------------------------------------------------------------------------------------------------------------
def getRandomSpeed(minSpeed, maxSpeed):
    #get mean in the log space
    logCenter = 1.42
    mu = np.log(logCenter)
    #standard deviation
    sigma = 0.1
    # get random values from dist
    randomValue = np.random.lognormal(mu, sigma, 1)
    randomValueClipped = np.clip(randomValue, minSpeed, maxSpeed)
    return randomValueClipped[0]


# -------------------------------------------------------------------------------------------------------------------------------
#   getTwoRandomPoints
# - get two random points in the simulation space in the area defined by x,y
# - points must have a euclidean distance within endpoint range, or else, regenerate
# -------------------------------------------------------------------------------------------------------------------------------
def getRandomPoint(start_point, endPointRange, node_num):
    fitCriteria = False
    while fitCriteria == False:
        randomPoint2 = (random.uniform(start_point[0]+node_num, start_point[0]+(node_num*3)), start_point[1]+node_num, start_point[1]+(node_num*3))
        if (getDistanceFromPoint(tuple(start_point), randomPoint2) >= endPointRange[0]) and (getDistanceFromPoint(tuple(start_point), randomPoint2) <= endPointRange[1]):
            fitCriteria = True
    return randomPoint2

#################################################################################################################################
#################################################################################################################################
### CHAIN
#################################################################################################################################
#################################################################################################################################

# -------------------------------------------------------------------------------------------------------------------------------
#   makeNewPath
# - add people at each arms length
# -------------------------------------------------------------------------------------------------------------------------------
def makeNewPath(path):
    armLength = 2 #PARAMETER! (distance between protestsers)
    newPath = []
    #create path (add people between the two points)
    for p in range(1,len(path)):
        newPath.append(path[p-1])
        pLen = getDistanceFromPoint(path[p], path[p-1])
        pplToAdd = round(pLen/armLength - 1)
        if pplToAdd > 0:
            #add new person 
            x_dif = (path[p][0] - path[p-1][0])/pplToAdd
            y_dif = (path[p][1] - path[p-1][1])/pplToAdd
            for i in range(pplToAdd):
                newPath.append((path[p-1][0]+(x_dif*i),path[p-1][1]+(y_dif*i)))
    newPath.append(path[len(path)-1])
    return newPath

# -------------------------------------------------------------------------------------------------------------------------------
#   assignChainPos
# - add protesters to their positions at correct times
# -------------------------------------------------------------------------------------------------------------------------------
def assignChainPos(newPath, seconds, node_num):
    #randomly assigned starting positions from above
    initialPositions = np.array([list(x) for x in list(newPath)])
    positions = np.zeros((seconds, node_num, 2))
    positions[0] = initialPositions
    # generate future positions (stable)
    for t in range(1, seconds):
        for i in range(node_num):
            positions[t][i] = positions[t - 1][i]
    return positions

# -------------------------------------------------------------------------------------------------------------------------------
#   getChain
# - get protester positions for chains
# -------------------------------------------------------------------------------------------------------------------------------
def getChain(start_pos, node_num):
    chainProtestPositions = np.empty((0,0,0)) 
    newPath = []
    
    while(len(newPath) != node_num):
        #get start and end points
        endpointRange = [node_num*1,node_num*5]
        chainEnd = getRandomPoint(start_pos, endpointRange, node_num)
        #generate initial chain path using linear interpolation
        numPointsPerCurve = round(random.uniform(0,10))
        numCurves = 1 #PARAMETER! (for chain curves)
        maxDeviation = 0.5 #PARAMETER! (for chain curves)
        path = generateSubtleCurves(tuple(start_pos), chainEnd, numPointsPerCurve, numCurves, maxDeviation)
        x_values, y_values = zip(*path)
        #make new initial chain path (more people)
        newPath = makeNewPath(path)
        #assign protester positions for time 

    positions = assignChainPos(newPath, seconds, node_num)

    #return array of chain protest positions
    return positions

#################################################################################################################################
#################################################################################################################################
### GATHER
#################################################################################################################################
#################################################################################################################################

# -------------------------------------------------------------------------------------------------------------------------------
#   assignFinalPos
#   - Assigns [protesterCount] number of protesters to random positions of at least [minDistance] away from eachother, within
#     the x,y plane represented by [xRange and yRange]
# -------------------------------------------------------------------------------------------------------------------------------
def assignFinalPos(xRange, yRange, protesterCount, minDistance):
    positions = {}
    # get lengths of plane
    # for each protester
    for i in range(protesterCount):
        # until you get a valid point, generate a new random point
        validPoint = False
        while validPoint == False:
            random_x, random_y = getRandomWithin(xRange[0], xRange[1], yRange[0], yRange[1])
            distanceFail = False
            # check if point fulfills conditions (is at least minDistance away from existing points)
            # if passes, add to starting positions. if fails, generate a point
            for point in positions:
                distance = getDistanceFromPoint((random_x, random_y), positions[point])
                if distance < minDistance:
                    distanceFail = True
            if distanceFail == False:
                positions['p'+str(i)] = (random_x, random_y)
                validPoint = True
    return positions

# -------------------------------------------------------------------------------------------------------------------------------
#   getGather
# - get protester positions for gather
# -------------------------------------------------------------------------------------------------------------------------------
def getGather(start_pos, node_num):
    gatherProtestPositions = np.empty((0,0,0)) 
    #for each sim
    crowdDensity = 1 #PARAMETER
    minDistance = .5 #PARAMETER
    # protester count is calculated based off of the size of the space and the density 
    # the size of the space is calculated based off of protester count and the density 
    area = node_num * crowdDensity
    yLen = math.sqrt(area)
    xLen = math.sqrt(area)
    # randomly assign positions based on density
    initialPositions = assignFinalPos((start_pos[0], start_pos[0]+xLen), (start_pos[1], start_pos[1]+yLen), node_num, minDistance)
    initialPositionsList = list(initialPositions.values())

    ##### -----------------------------------------------------------------------------------------------------------------------
    ##### We then select a small subset of nodes at each interval to move within the space. To simulate this random 
    ##### movement, we adopt the random waypoint model, selecting a random location, and a random speed within a range 
    ##### of reasonable walking speeds. This continues until the end of the gathering simulation.
    ##### -----------------------------------------------------------------------------------------------------------------------
    #select moving nodes
    subsetMoving = .1
    movingNodes = []
    all = list(range(0,node_num))
    toSelect = int(len(all) * subsetMoving)
    movingNodes = random.sample(all, toSelect)
    #randomly assigned starting positions from above
    initialPositions = np.array([list(x) for x in initialPositionsList])
    #set pause and total tile
    minPause = 0
    maxPause = 50

    positions = np.zeros((seconds, node_num, 2))
    positions[0] = initialPositions
    #for each protester:
    for p in range(node_num):
        # if not a moving node
        if p not in movingNodes:
            # first, nodes pause
            nodePauseLen = round(random.uniform(minPause, maxPause))
            for i in range(1,seconds):
                positions[i][p] = positions[i-1][p]
        # else, it is a moving node
        else:
            currTime=0
            while currTime < seconds:
                # first, nodes pause
                nodePauseLen = round(random.uniform(minPause, maxPause))
                #nodePauseLen = 1
                # assign same position from start for duration of pause
                if (nodePauseLen+currTime >= seconds):
                    iterations = seconds - currTime 
                else:
                    iterations = nodePauseLen +1
                
                for i in range(currTime+1,currTime+iterations):
                    positions[i][p] = positions[i-1][p]
                #then generate future positions
                currTime = currTime + nodePauseLen

                if currTime >= seconds:
                    break

                # select random location
                randomPoint = getRandomWithin(start_pos[0], start_pos[0]+xLen, start_pos[1], start_pos[1]+yLen)
                
                # select speed 
                minSpeed = .05
                maxSpeed = .4
                randomSpeed = getRandomSpeed(minSpeed, maxSpeed)
                # get time it would take to get to new random location
                distanceBetween = getDistanceFromPoint(randomPoint, (positions[currTime][p][0], positions[currTime][p][1]))
                timeToTraverse = math.ceil(distanceBetween/randomSpeed)
                stops = generatePointsBetween(positions[currTime][p], list(randomPoint), timeToTraverse)
                stopNum = 0
                if (timeToTraverse+currTime >= seconds):
                    iterations = seconds - currTime
                else:
                    iterations = timeToTraverse +1
                for t in range(iterations):
                    positions[t+currTime][p] = stops[stopNum]
                    stopNum+=1
                currTime = currTime + timeToTraverse 

    if(np.size(gatherProtestPositions) != 0):
        gatherProtestPositions = np.concatenate((gatherProtestPositions, positions), axis=1)
    else:
        gatherProtestPositions = positions
    #return array of chain protest positions

    return gatherProtestPositions


#################################################################################################################################
#################################################################################################################################
### BLOCKADE
#################################################################################################################################
#################################################################################################################################
# -------------------------------------------------------------------------------------------------------------------------------
# PARAMETER VALS
# -------------------------------------------------------------------------------------------------------------------------------
# proDepth --- the number of "lines" of protesters that are formed at the blockade (aka the crowdedness/# of protesters)
proDepth = 10

# copDepth --- the number of "lines" of cops that are formed at the blockade (aka the crowdedness/# of cops)
copDepth = 4
# distanceApart --- how far apart nodes are (protesters or cops)
distanceApart = 2
# depthDistance --- the distance between initial lines being formed of the same type (i.e. betweeen lines of protesters)
depthDistance = 1
#  initialDistanceBetween --- how far the first cop line should be from the first of the protester lines
initialDistanceBetween = .5
# protesterClumpCount --- the number of clumps which the protesters should be clumped into to pick up supplies or retreat to
protesterClumpCount = 3
# noiseRange --- the max amount of noise in any direction that can be added to a protester's assigned block position 
#                [to introduce randomness]
noiseRange = 1.5
# copClumpCount --- the number of clumps which the cops should be clumped into to pick up supplies or retreat to
copClumpCount = 3
# timeThreshold --- the amount of time that 2 nodes must be close to generate potential conflict/cause retreat
timeThreshold = 30
# distanceThreshold --- the max distance that a node can be from their blockade position to be considered at the blockade 
distanceThreshold = .2
# conflictDistanceThreshold --- the closeness of distance that 2 nodes must be to generate potential conflict/cause retreat
conflictDistanceThreshold = distanceThreshold/2
# distance ---
distance = 2
# thresholdDist ---
thresholdDist = 1
# ratioValue --- the ratio at which protesters or cops at the blockade are "overwhelmed" and must retreat
#                [i.e. 2 would mean twice as many cops as protesters, protesters retreat]
#                [whereas .5 would mean twice as many protesters as cops, retreat]
ratioValue = 2
# StationaryNoise --- the max amount of noise added to a node's position in any direction when they are 
#                     "stationary" (staying at blockade line)
stationaryNoise = .25 
# maxDistPerIter --- the maximum distance a node can travel in one iteration (one second)
maxDistPerIter = 1.4

# -------------------------------------------------------------------------------------------------------------------------------
#   makeInitialLines
# - make <depth value> # of parallel lines, with initially generated random line of endpoint range
# - returned as list of [(start x,y), (end x,y)]  for each line
# - distance between lines = depthDistance * depth
# -------------------------------------------------------------------------------------------------------------------------------
def makeInitialLines(xRange,yRange, depth, depthDistance, endpointRange):
    lines = []
    #get starting line and add to list
    lines.append(getTwoRandomPoints(xRange,yRange, endpointRange))
    direction = random.choice([0, 1])
    # generate (depth -1) # of additional parallel lines & append to list
    for d in range(1,depth):
        distanceBetween = d * depthDistance
        lines.append(getParallelLines(lines[d-1][0][0], lines[d-1][0][1], lines[d-1][1][0], lines[d-1][1][1], distanceBetween)[direction])
    return lines, direction

# -------------------------------------------------------------------------------------------------------------------------------
#   makeNewPath
# - add people at appropriate distances on path line (appropriate distance determined by distanceApart)
# - returns new path
# -------------------------------------------------------------------------------------------------------------------------------
def assignToPath(path, depth, distanceApart):
    newPath = []
    for p in range(1,len(path)):
        newPath.append(path[p-1])
        # length of path
        pLen = math.sqrt((path[p][0] - path[p-1][0])**2 + (path[p][1] - path[p-1][1])**2)
        # add people of approximately depth/distance apart
        pplToAdd = round(pLen/(distanceApart) - 1)
        if pplToAdd > 0:
            #add new person 
            x_dif = (path[p][0] - path[p-1][0])/pplToAdd
            y_dif = (path[p][1] - path[p-1][1])/pplToAdd
            for i in range(pplToAdd):
                newPath.append((path[p-1][0]+(x_dif*i),path[p-1][1]+(y_dif*i)))
    newPath.append(path[len(path)-1])
    return newPath

# -------------------------------------------------------------------------------------------------------------------------------
#   noisePath
# - given current protester positions on path, add noise within <noise range> to the path
# - plot the protester positions after noise is added (first in groups and then not in groups)
# -------------------------------------------------------------------------------------------------------------------------------
def noisePath(pathLines, noiseRange):
    # add noise and assign as new positions
    newPathLines = []
    for path in pathLines:
        newPath = []
        for p in path:
            p0 = p[0] + random.uniform(-1*noiseRange, noiseRange)
            p1 = p[1] + random.uniform(-1*noiseRange, noiseRange)
            newPath.append((p0, p1))
        newPathLines.append(newPath)
    finalPath = []
    for i in range(len(newPathLines)):
        finalPath = finalPath + newPathLines[i]
    
    return finalPath

# -------------------------------------------------------------------------------------------------------------------------------
#   chooseClumps
# - generates a number of clumps that are away from the blockade line (outside of line 1, and outside of line 2)
# -------------------------------------------------------------------------------------------------------------------------------
def chooseClumps(xRange, yRange, protesterClumpCount, line1, line2, clumpDistance):
    #expand first line in chain to entire space within xRange, yRange
    lineEquation = findLineEquation(line1[0], line1[1])
    #figure out if want above or below the line
    lineEquation2 = findLineEquation(line2[0], line2[1])
    #want above
    compareEquations = (lineEquation(1) < lineEquation2(1))
    above = True if compareEquations else False
    #rotate until find suitable point
    clumps = []
    for clump in range(protesterClumpCount):
        fitCriteria = False
        tries = 0
        while (not fitCriteria) and (tries < 100000):
            tries+=1
            randomPoint = (random.uniform(xRange[0], xRange[1]), random.uniform(yRange[0], yRange[1]))
            #if need point above
            if above:
                # if point is above line and at least given distance from the line 
                if randomPoint[1] > lineEquation(randomPoint[0]) and (distanceToLine(randomPoint[0], randomPoint[1], findSlope(line1[0], line1[1]), findIntercept(line1[0], line1[1]))>clumpDistance):
                    fitCriteria = True
                    clumps.append(randomPoint)
            #if need point below
            else:
                # if point is above line and at least given distance from the line 
                if (randomPoint[1] < lineEquation(randomPoint[0])) and (distanceToLine(randomPoint[0], randomPoint[1], findSlope(line2[0], line2[1]), findIntercept(line2[0], line2[1]))>clumpDistance):
                    fitCriteria = True
                    clumps.append(randomPoint)
    return clumps

# -------------------------------------------------------------------------------------------------------------------------------
#   assignClumps
# - assign each protester to the closest "supply clump" such that protesters are divided roughly equally between groups
# -------------------------------------------------------------------------------------------------------------------------------
def assignClumps(finalPath, clumps):
    sorted_points = sorted(finalPath, key=lambda p: min(getDistanceFromPoint(p, rp) for rp in clumps))
    groups = [sorted_points[i::len(clumps)] for i in range(len(clumps))]
    return groups

# -------------------------------------------------------------------------------------------------------------------------------
#   doClumps
# - generate clumps & assign protesters to clumps they will traverse between
# -------------------------------------------------------------------------------------------------------------------------------
def doClumps(finalPath, protesterClumpCount, line1, line2, clumpDistance, xRange, yRange):
    #choose positions for clumps
    clumpPositions = chooseClumps(xRange, yRange, protesterClumpCount, line1, line2, clumpDistance)
    #assign protesters to clumps
    if len(clumpPositions) != protesterClumpCount:
        proClumpGroups = []
    else:
        proClumpGroups = assignClumps(finalPath, clumpPositions)
    return clumpPositions, proClumpGroups

# -------------------------------------------------------------------------------------------------------------------------------
#   setPaths
# - create data structures for starts, blocks, and initial dests
# - assign each accordingly, generating a clump position with some noise added
# -------------------------------------------------------------------------------------------------------------------------------
def setPaths(finalPath, proClumpGroups, clumpPositions, noiseRange):
    #tracks where protesters want to go in blockade
    blocks = [None]*len(finalPath)
    # tracks where protesters want to go for clump
    starts = [None]*len(finalPath)
    #tracks protester current destination
    dests = [None]*len(finalPath)
    #assign to starting positions
    for p in range(len(finalPath)):
        for g in range(len(proClumpGroups)):
            if finalPath[p] in proClumpGroups[g]:
                blocks[p] = finalPath[p]
                dests[p] = finalPath[p]
                p0 = clumpPositions[g][0] + random.uniform(-1*noiseRange, noiseRange)
                p1 = clumpPositions[g][1] + random.uniform(-1*noiseRange, noiseRange)
                starts[p] = (p0, p1)
    return starts, blocks, dests

# -------------------------------------------------------------------------------------------------------------------------------
#   generateInitialPos
# - given starting positions, create and fill data structure to store all positions
# -------------------------------------------------------------------------------------------------------------------------------
def generateInitialPos(seconds, starts):
    initialPositions = np.array([list(x) for x in list(starts)])
    time = np.arange(seconds)
    positions = np.zeros((seconds, len(initialPositions), 2))
    positions[0] = initialPositions
    return positions

# -------------------------------------------------------------------------------------------------------------------------------
#   getNextPoint
# - given 2 points, get the point __ meters away from p1 on the line formed by p1 and p2
# -------------------------------------------------------------------------------------------------------------------------------
def getNextPoint(p1, p2, distance):
    #slope and intercept of the line passing through p1 and p2
    slope = (p2[1] - p1[1]) / (p2[0] - p1[0])
    intercept = p1[1] - slope * p1[0]
    # Calculate the length of the line segment between p1 and p2
    segmentLen = math.sqrt((p2[0] - p1[0])**2 + (p2[1] - p1[1])**2)
    # Calculate the coordinates of the point N meters away from p1 on the line
    xnew = p1[0] + (distance / segmentLen) * (p2[0] - p1[0])
    ynew = p1[1] + (distance / segmentLen) * (p2[1] - p1[1])
    return (xnew, ynew)

# -------------------------------------------------------------------------------------------------------------------------------
#   getHop
# - given 2 points and the distance they can travel in one iteration, get the position for the next iteration
# -------------------------------------------------------------------------------------------------------------------------------
def getHop(currLoc, currDest, distance, maxDistPerIter):     
    #get next hop to get to position
    distRemain = getDistanceFromPoint(currLoc, currDest)
    #if dist remain small enough, next hop is dest 
    if distRemain <= maxDistPerIter:
        nextHop = currDest
    #else, proceed generally in way of next hop
    else:
        nextHop = getNextPoint(currLoc, currDest, distance)
    return nextHop 

# -------------------------------------------------------------------------------------------------------------------------------
#   getNextHop
# - given protester position information, get current distance from destination
# - if it's not there yet, assign the next position to go there
# - if it is at destination, assign next position to other destination (clump or to block position)
# -------------------------------------------------------------------------------------------------------------------------------
def getNextHop(protesterBlock, protesterDest, protesterStart, position, thresholdDist, distance, maxDistPerIter):
    #given current position and current destination; if current position == approx current destination
    nextProtesterDest = ()
    nextPosition = ()
    #if it's close enough to its destination point
    if getDistanceFromPoint(tuple(position), tuple(protesterDest)) < thresholdDist:
        #set new destination (switch to either clump or start positions respectively)
        if getDistanceFromPoint(protesterDest, protesterStart) < thresholdDist:
            nextProtesterDest = protesterBlock
        elif getDistanceFromPoint(protesterDest, protesterBlock) < thresholdDist: 
            nextProtesterDest = protesterStart
        else:
            nextProtesterDest = protesterDest
        nextPosition = position
    #else, keep traversing 
    else:
        #set next hop generally in direction of destination
        nextProtesterDest = protesterDest
        nextPosition = getHop(position, nextProtesterDest, distance, maxDistPerIter)
    return nextPosition, nextProtesterDest

# -------------------------------------------------------------------------------------------------------------------------------
#   makeCopLines
# - given lines of protesters, make parallel lines in opposite direction (same as makeInitialLines, but with different starting point)
# -------------------------------------------------------------------------------------------------------------------------------
def makeCopLines(protestLine, depth, direction):
    lines = []
    #get parallel line 
    lines.append(getParallelLines(protestLine[0][0], protestLine[0][1], protestLine[1][0], protestLine[1][1], initialDistanceBetween)[direction])
    for d in range(1,depth):
        #get parallel line
        distanceBetween = d * depthDistance
        lines.append(getParallelLines(lines[d-1][0][0], lines[d-1][0][1], lines[d-1][1][0], lines[d-1][1][1], distanceBetween)[direction])
    return lines

# -------------------------------------------------------------------------------------------------------------------------------
#   getCopToProtesterRatio
# - get the ratio of cops on their positions on the line to the ratio of protesters on their positions on the line
# -------------------------------------------------------------------------------------------------------------------------------
def getCopToProtesterRatio(proPositions, copPositions, protesterBlocks, copBlocks, distanceThreshold):
    # for all protesters, check and see if their current position is close (~_ m from their block position)
    protestersOnBlockLine = 0
    for p in range(len(proPositions)):
        if getDistanceFromPoint(protesterBlocks[p], proPositions[p]) < distanceThreshold:
            protestersOnBlockLine += 1
    # for all cops, check and see if their current position is close (~ _ m from their block position)
    copsOnBlockLine = 0
    for c in range(len(copPositions)):
        if getDistanceFromPoint(copBlocks[c], copPositions[c]) < distanceThreshold:
            copsOnBlockLine += 1
    # return ratio
    if (copsOnBlockLine==0) or (protestersOnBlockLine==0):
        return -1
    else:
        return copsOnBlockLine/protestersOnBlockLine

# -------------------------------------------------------------------------------------------------------------------------------
#   getScatterStatus
# - returns whether protesters or cops should be scattering (if they are outnumbered <ratio-value> to 1)
# -------------------------------------------------------------------------------------------------------------------------------
def getScatterStatus(proPositions, copPositions, protesterBlocks, copBlocks, ratioValue, distanceThreshold):
    #calculate cop-protester ratio (higher = more cops)
    proScatter = False
    copScatter = False
    ratio = getCopToProtesterRatio(proPositions, copPositions, protesterBlocks, copBlocks, distanceThreshold)
    #if way more cops:
    if ratio > ratioValue:
        #protesters scatter
        proScatter = True
    elif (ratio < (1/ratioValue)) and (ratio > 0):
        #cops scatter
        copScatter = True
    return proScatter, copScatter

# -------------------------------------------------------------------------------------------------------------------------------
#   pointToLine
# - returns the distance from a point the line represented by linepoint1&2
# -------------------------------------------------------------------------------------------------------------------------------
def pointToLine(point, linePoint1, linePoint2):
    x0, y0 = point
    x1, y1 = linePoint1
    x2, y2 = linePoint2
    A = y2 - y1
    B = x1 - x2
    C = (x2 - x1) * y1 - (y2 - y1) * x1
    distance = abs(A * x0 + B * y0 + C) / math.sqrt(A**2 + B**2)
    return distance

# -------------------------------------------------------------------------------------------------------------------------------
#   positionIsAwayFromBlock
# - returns whether going to the current destination is further away from the blockade than the current position 
# -------------------------------------------------------------------------------------------------------------------------------
def positionIsAwayFromBlock(protesterDest, proPosition, blockPos1, blockPos2):
    currDistanceFromBlock = pointToLine(proPosition, blockPos1, blockPos2)
    destDistanceFromBlock = pointToLine(protesterDest, blockPos1, blockPos2)
    if currDistanceFromBlock < destDistanceFromBlock:
        return True
    else:
        return False

# -------------------------------------------------------------------------------------------------------------------------------
#   scatterNextHop
# - if current destination isnt away from the blockade, choose a new random position away from the blockade to go to
# - otherwise keep current destination
# - get next hop from current position toward that destination
# -------------------------------------------------------------------------------------------------------------------------------
def scatterNextHop(protesterBlock, protesterDest, protesterStart, proPosition, chain0, chain1, thresholdDist, distance, xRange, yRange):
    while (positionIsAwayFromBlock(protesterDest, proPosition, chain0[0], chain0[1]) == False):   
            # pick a random spot away from block and flee there
            clumpDistance = 10
            protesterDest = chooseClumps(xRange, yRange, protesterClumpCount, chain0, chain1, clumpDistance)[0]
    nextPosition, nextProtesterDest = getNextHop(protesterBlock, protesterDest, protesterStart, proPosition, thresholdDist, distance, maxDistPerIter)
    if(nextProtesterDest == ()):
        print("FML")
    #print(nextPosition, nextProtesterDest)
    return nextPosition, nextProtesterDest

# -------------------------------------------------------------------------------------------------------------------------------
#   copChaseNextHop
# - cop tries to get to location ("chase") of closest protester
# -------------------------------------------------------------------------------------------------------------------------------
def copChaseNextHop(copBlock, copDest, copStart, copPosition, proPositions, thresholdDist, distance):
    #find closest protester
    closest = 99999999
    closest_idx = 99999999
    #get closest protester
    for pro in range(len(proPositions)):
        dist = getDistanceFromPoint(copPosition, proPositions[pro])
        if (dist < closest):
            closest = dist
            closest_idx = pro
    # set destination to closest protester and get next hop
    nextPosition, nextProtesterDest = getNextHop(copBlock, proPositions[closest_idx], copStart, copPosition, thresholdDist, distance, maxDistPerIter)
    return nextPosition, proPositions[closest_idx]

# -------------------------------------------------------------------------------------------------------------------------------
#   proScatter
# - gets next positions for all cops and protesters given protesters are now scattering
# - protesters go random directions away from blockade
# - cops try to follow a protester
# -------------------------------------------------------------------------------------------------------------------------------
def proScatter(t, protesterBlocks, protesterDests, protesterStarts, proPositions, chain0, chain1, copBlocks, copDests, copStarts, copPositions, distance, xRange, yRange):
    for p in range(len(protesterBlocks)):
        #scatter (go in random direction)
        #print("AH", p, len(protesterDests[p]), len(protesterBlocks[p]), protesterDests[p], protesterBlocks[p])
        backup = protesterDests[p]
        pval, dval = scatterNextHop(protesterBlocks[p], protesterDests[p], protesterStarts[p], proPositions[t-1][p], chain0, chain1, thresholdDist, distance, xRange, yRange)
        proPositions[t][p], protesterDests[p] = pval, dval
        #chase closest protester
        copPositions[t][p], copDests[p] = copChaseNextHop(copBlocks[p], copDests[p], copStarts[p], copPositions[t-1][p], proPositions[t-1], thresholdDist, distance)
    return proPositions, protesterDests, copPositions, copDests


# -------------------------------------------------------------------------------------------------------------------------------
#   stayPut
# - add a bit of noise to position, but more or less set next position to stay put
# -------------------------------------------------------------------------------------------------------------------------------
def stayPut(block, dest, start, position, noiseAmount):
    nextPosition  = (position[0]+random.uniform(-1*noiseAmount, 1*noiseAmount), position[1]+random.uniform(-1*noiseAmount, 1*noiseAmount))
    return nextPosition, dest

# -------------------------------------------------------------------------------------------------------------------------------
#   copRetreatNextHop
# - set destination to cop start (cluster position), where they should be retreating to
# -------------------------------------------------------------------------------------------------------------------------------
def copRetreatNextHop(copBlock, copDest, copStart, copPosition, distance):
    nextPosition, nextCopDest = getNextHop(copBlock, copStart, copStart, copPosition, thresholdDist, distance, maxDistPerIter)
    return nextPosition, nextCopDest

# -------------------------------------------------------------------------------------------------------------------------------
#   copScatter
# - gets next positions for all cops and protesters given cops are now scattering
# - protesters stay put
# - cops go in random directions away from blockade
# -------------------------------------------------------------------------------------------------------------------------------
def copScatter(t, protesterBlocks, protesterDests, protesterStarts, proPositions, chain0, chain1, copBlocks, copDests, copStarts, copPositions, stationaryNoise):
    for p in range(len(protesterDests)):
        #have protesters maintain their current positions
        nextProPosition, nextProtesterDest = stayPut(protesterBlocks[p], protesterDests[p], protesterStarts[p], proPositions[t-1][p], stationaryNoise)
        proPositions[t][p] = nextProPosition
        protesterDests[p] = nextProtesterDest
        #have cops retreat back to their clumps
    for p in range(len(copDests)):
        nextCopPosition, nextCopDest = copRetreatNextHop(copBlocks[p], copDests[p], copStarts[p], copPositions[t-1][p], distance)
        copPositions[t][p] = nextCopPosition
        copDests[p] = nextCopDest
    return proPositions, protesterDests, copPositions, copDests

# -------------------------------------------------------------------------------------------------------------------------------
#   proRetreatNextHop
# - protester goes back to original cluster position
# -------------------------------------------------------------------------------------------------------------------------------
def proRetreatNextHop(protesterBlock, protesterDest, protesterStart, proPosition, distance):
    nextPosition, nextProtesterDest = getNextHop(protesterBlock, protesterStart, protesterStart, proPosition, thresholdDist, distance, maxDistPerIter)
    return nextPosition, nextProtesterDest
    
# -------------------------------------------------------------------------------------------------------------------------------
#   opInSurroundingTimeout
# - determines whether an op has been in the given protester's surroundings dating back for the appropriate time threshold
# -------------------------------------------------------------------------------------------------------------------------------
def opInSurroundingTimeout(yourPositions, opPositions, p, t, closeThreshold, timeThreshold):
    if t > timeThreshold:
        for op in range(opPositions.shape[1]):
            if (getDistanceFromPoint(yourPositions[t][p], opPositions[t][op]) <= closeThreshold):
                isInConflict = 1
                for time in range(t-timeThreshold, t):
                    if (getDistanceFromPoint(yourPositions[time][p], opPositions[time][op]) > closeThreshold):
                        isInConflict = 0
                if isInConflict == 1:
                    return True
    return False

# -------------------------------------------------------------------------------------------------------------------------------
#   shouldProtesterRetreat
# - given if there is conflict (op in surroundings for certain time) randomly generate whether pro should retreat 
# - returns 0 if protester did not retreat, 1 if protester positions have been updated to retreat
# -------------------------------------------------------------------------------------------------------------------------------
def shouldProtesterRetreat(protesterBlocks, protesterDests, protesterStarts, proPositions, copBlocks, copDests, copStarts, copPositions, p, t, conflictDistanceThreshold, timeThreshold, distance):
    # get retreat status for protester (is there a local threat and has it timed out)
    if opInSurroundingTimeout(proPositions, copPositions, p, t, conflictDistanceThreshold, timeThreshold):
            # get whether protester should retreat
            shouldRetreat = random.choices([0,1], weights=[2,1], k=1)
            if shouldRetreat[0]:
                #if pro retreat
                nextProPosition, nextProtesterDest = proRetreatNextHop(protesterBlocks[p], protesterDests[p], protesterStarts[p], proPositions[t-1][p], distance)
                proPositions[t][p] = nextProPosition
                protesterDests[p] = nextProtesterDest
                return proPositions, protesterDests
    return proPositions, protesterDests

# -------------------------------------------------------------------------------------------------------------------------------
#   shouldCopRetreat
# - given if there is conflict (op in surroundings for certain time) randomly generate whether pro should retreat 
# - returns 0 if protester did not retreat, 1 if protester positions have been updated to retreat
# -------------------------------------------------------------------------------------------------------------------------------
def shouldCopRetreat(protesterBlocks, protesterDests, protesterStarts, proPositions, copBlocks, copDests, copStarts, copPositions, p, t, conflictDistanceThreshold, timeThreshold):
    # get retreat status for cop
    if opInSurroundingTimeout(copPositions, proPositions, p, t, conflictDistanceThreshold, timeThreshold):
        shouldRetreat = random.choices([0,1], weights=[.75, .25], k=1)
        if shouldRetreat[0]:
            nextCopPosition, nextCopDest = copRetreatNextHop(copBlocks[p], copDests[p], copStarts[p], copPositions[t-1][p], distance)
            copPositions[t][p] = nextCopPosition
            copDests[p] = nextCopDest
            return copPositions, copDests
    return copPositions, copDests
        
# -------------------------------------------------------------------------------------------------------------------------------
#   doProtester
# - if protester position is not already set, if protester is already at blockade, 
# -------------------------------------------------------------------------------------------------------------------------------
def doProtester(protesterBlocks, protesterDests, protesterStarts, proPositions, p, t, distanceThreshold, stationaryNoise):
    if (getDistanceFromPoint(proPositions[t-1][p], protesterBlocks[p]) < distanceThreshold):
        nextProPosition, nextProtesterDest = stayPut(protesterBlocks[p], protesterBlocks[p], protesterStarts[p], proPositions[t-1][p], stationaryNoise)
        proPositions[t][p] = nextProPosition
        protesterDests[p] = nextProtesterDest
    else:
        nextProPosition, nextProtesterDest = getNextHop(protesterBlocks[p], protesterBlocks[p], protesterStarts[p], proPositions[t-1][p], thresholdDist, distance, maxDistPerIter)
        proPositions[t][p] = nextProPosition
        protesterDests[p] = nextProtesterDest
    return proPositions, protesterDests

# -------------------------------------------------------------------------------------------------------------------------------
#   doCop
# - given if there is conflict (op in surroundings for certain time) randomly generate whether cop should retreat 
# - returns 0 if cop did not retreat, 1 if protester positions have been updated to retreat
# -------------------------------------------------------------------------------------------------------------------------------
def doCop(copBlocks, copDests, copStarts, copPositions, p, t, distanceThreshold, stationaryNoise):
    if (getDistanceFromPoint(copPositions[t-1][p], copBlocks[p]) < distanceThreshold):
        nextCopPosition, nextCopDest = stayPut(copBlocks[p], copDests[p], copStarts[p], copPositions[t-1][p], stationaryNoise)
        copPositions[t][p] = nextCopPosition
        copDests[p] = nextCopDest
    else:
        nextCopPosition, nextCopDest = getNextHop(copBlocks[p], copDests[p], copStarts[p], copPositions[t-1][p], thresholdDist, distance, maxDistPerIter)
        copPositions[t][p] = nextCopPosition
        copDests[p] = nextCopDest
    return copPositions, copDests

# -------------------------------------------------------------------------------------------------------------------------------
#   getBlockade1
# - get protester positions for blockade 1
# -------------------------------------------------------------------------------------------------------------------------------
def getBlockade1(start_pos, node_num):
    blockProtestPositions = np.empty((0,0,0)) 
    p_count = 0
    while p_count != node_num:
        #for each chain sim
        #get start and end points for chain -- based on random points in range that are within distance endpoint range
        proDepth = round(random.uniform(2,3))
        #proDepth = 2
        depthDistance = 1
        endpointRange = [node_num/2, node_num*2]
        proLines, direction = makeInitialLines((start_pos[0], start_pos[0]+node_num+100), (start_pos[1], start_pos[1]+node_num+100), proDepth, depthDistance, endpointRange)
        #make new initial chain path (more people)
        distanceApart = 2
        proPathLines = generatePointsAlongLines(proLines, proDepth, distanceApart)
        noiseRange = 1.5
        finalProPath = noisePath(proPathLines, noiseRange)
        #get area clumps protesters would be coming from (starting positions)
        protesterClumpCount = 3
        clumpDistance = 10
        proClumpPositions, proClumpGroups = doClumps(finalProPath, protesterClumpCount, proLines[0], proLines[1], clumpDistance, (start_pos[0], start_pos[0]+node_num+100), (start_pos[1], start_pos[1]+node_num+100))
        if len(proClumpGroups) == 0:
            print("FAILED")
            continue
        #get notable positions in paths
        protesterStarts, protesterBlocks, protesterDests = setPaths(finalProPath, proClumpGroups, proClumpPositions, noiseRange)
        #SCENARIO 1: place objects blockade (protesters place stuff and retreat)
        #generate initial pos
        positions = generateInitialPos(seconds, protesterStarts)
        p_count = len(positions[0])
        print(p_count)
    
    #generate future positions 
    for t in range(1, seconds):
        #for each protester
        for p in range(len(positions[0])):
            #generate next hop in direction of block line or clump
            thresholdDist = 1
            distance = 2
            maxDistPerIter = 1.4
            positions[t][p], protesterDests[p] = getNextHop(protesterBlocks[p], protesterDests[p], protesterStarts[p], positions[t-1][p], thresholdDist, distance, maxDistPerIter)
    #blockProtesterCount += len(positions[0])
    if(np.size(blockProtestPositions) != 0):
        blockProtestPositions = np.concatenate((blockProtestPositions, positions), axis=1)
    else:
        blockProtestPositions = positions
    #return array of chain protest positions
    return blockProtestPositions

# -------------------------------------------------------------------------------------------------------------------------------
#   getBlockade2
# - get protester positions for blockade 2
# -------------------------------------------------------------------------------------------------------------------------------
def getBlockade2(start_pos, node_num):

    blockProtestPositions = np.empty((0,0,0)) 
    p_count = 0
    while p_count != node_num:
        #for each chain sim
        #get start and end points for chain -- based on random points in range that are within distance endpoint range
        proDepth = round(random.uniform(2,3))
        #proDepth = 2
        depthDistance = 1
        endpointRange = [node_num/2, node_num*2]
        proLines, direction = makeInitialLines((start_pos[0], start_pos[0]+node_num+100), (start_pos[1], start_pos[1]+node_num+100), proDepth, depthDistance, endpointRange)
        #make new initial chain path (more people)
        distanceApart = 2
        proPathLines = generatePointsAlongLines(proLines, proDepth, distanceApart)
        noiseRange = 1.5
        finalProPath = noisePath(proPathLines, noiseRange)
        #get area clumps protesters would be coming from (starting positions)
        protesterClumpCount = 3
        clumpDistance = 10
        proClumpPositions, proClumpGroups = doClumps(finalProPath, protesterClumpCount, proLines[0], proLines[1], clumpDistance, (start_pos[0], start_pos[0]+node_num+100), (start_pos[1], start_pos[1]+node_num+100))
        if len(proClumpGroups) == 0:
            print("FAILED")
            continue
        #get notable positions in paths 
        protesterStarts, protesterBlocks, protesterDests = setPaths(finalProPath, proClumpGroups, proClumpPositions, noiseRange)
        #SCENARIO 1: place objects blockade (protesters place stuff and retreat)
        #generate initial pos
        positions = generateInitialPos(seconds, protesterStarts)
        p_count = len(positions[0])
        print(p_count)

    
    
    #flip the direction of the protesters
    if direction==0:
        copLines = makeCopLines(proLines[0], copDepth, 1)
    else:
        copLines = makeCopLines(proLines[0], copDepth, 0)
    #generate cop positions
    copPathLines = generatePointsAlongLines(copLines, copDepth, distanceApart)
    #noise initial cop positions
    finalCopPath = noisePath(copPathLines, noiseRange)
    #get area clumps protesters would be coming from (starting positions)
    copClumpPositions, copClumpGroups = doClumps(finalCopPath, copClumpCount, copLines[0], copLines[1], clumpDistance, (start_pos[0], start_pos[0]+node_num+100), (start_pos[1], start_pos[1]+node_num+100))
    #get notable positions in cop paths 
    copStarts, copBlocks, copDests = setPaths(finalCopPath, copClumpGroups, copClumpPositions, noiseRange)
    #generate initial pos
    proPositions = generateInitialPos(seconds, protesterStarts)
    copPositions = generateInitialPos(seconds, copStarts)
    #not scattering at start
    proScatterBool = False
    copScatterBool = False

    #generate future positions
    for t in range(1, seconds):
        print(t)
        file_name = "status_" + str(nodecount) + ".txt"
        with open(file_name, 'a') as file:
            file.write(str(t)+"\n")
        file.close()
        # if it's time to start checking for scatter
        if t > timeThreshold:
            #check if cop or protester should scatter
            if (proScatterBool == False) and (copScatterBool == False):
                proScatterBool, copScatterBool = getScatterStatus(proPositions[t-1], copPositions[t-1], protesterBlocks, copBlocks, ratioValue, distanceThreshold)
            #if protesters should scatter
            if proScatterBool:
                proPositions, protesterDests, copPositions, copDests = proScatter(t, protesterBlocks, protesterDests, protesterStarts, proPositions, proLines[0], proLines[1], copBlocks, copDests, copStarts, copPositions, distance, (start_pos[0], start_pos[0]+node_num+100), (start_pos[1], start_pos[1]+node_num+100))
                continue
            #if cops should scatter
            elif copScatterBool:
                proPositions, protesterDests, copPositions, copDests = copScatter(t, protesterBlocks, protesterDests, protesterStarts, proPositions, copLines[0], copLines[1], copBlocks, copDests, copStarts, copPositions, stationaryNoise)
                continue
        #else, stay on block line, and simulate blockade
        # check if cop or protester should retreat
        for p in range(len(proPositions[0])):
            proPositions, protesterDests= shouldProtesterRetreat(protesterBlocks, protesterDests, protesterStarts, proPositions, copBlocks, copDests, copStarts, copPositions, p, t, conflictDistanceThreshold, timeThreshold, distance)
        for p in range(len(copPositions[0])):    
            copPositions, copDests = shouldCopRetreat(protesterBlocks, protesterDests, protesterStarts, proPositions, copBlocks, copDests, copStarts, copPositions, p, t, conflictDistanceThreshold, timeThreshold)
        for p in range(len(proPositions[0])):
            proPositions, protesterDests = doProtester(protesterBlocks, protesterDests, protesterStarts, proPositions, p, t, distanceThreshold, stationaryNoise)
        for p in range(len(copPositions[0])):    
            copPositions, copDests = doCop(copBlocks, copDests, copStarts, copPositions, p, t, distanceThreshold, stationaryNoise)
    return proPositions

#################################################################################################################################
#################################################################################################################################
### MARCH
#################################################################################################################################
#################################################################################################################################

# -------------------------------------------------------------------------------------------------------------------------------
#   assignFinalPosMarch
#   - Assigns [protesterCount] number of protesters to random positions of at least [minDistance] away from eachother, within
#     the x,y plane represented by [xRange and yRange]
# -------------------------------------------------------------------------------------------------------------------------------
def assignFinalPosMarch(xRange, yRange, protesterCount, minDistance):
    positions = {}
    # get lengths of plane
    xLen = xRange[1]-xRange[0]
    yLen = yRange[1]-yRange[0]
    # for each protester
    for i in range(protesterCount):
        # until you get a valid point, generate a new random point
        validPoint = False
        while validPoint == False:
            random_x, random_y = getRandomWithin(xRange[0], xRange[1], yRange[0], yRange[1])
            distanceFail = False
            # check if point fulfills conditions (is at least minDistance away from existing points)
            # if passes, add to starting positions. if fails, generate a point
            for point in positions:
                distance = getDistanceFromPoint((random_x, random_y), positions[point])
                if distance < minDistance:
                    distanceFail = True
            if distanceFail == False:
                positions['p'+str(i)] = (random_x, random_y)
                validPoint = True
    return positions

# -------------------------------------------------------------------------------------------------------------------------------
#   getMarch
# - get protester positions for march
# -------------------------------------------------------------------------------------------------------------------------------
def getMarch(start_pos, node_num):
    marchProtestPositions = np.empty((0,0,0)) 
    marchProtesterCount = 0
    # assign range of x,y plane where protesters are located in meters 
    # (not the simulation space, but within greater simulation space)
    crowdDensity = 2.5 #PARAMETER 
    minDistance = .5 #PARAMETER
    street_len = 16

    area1 = round(.6 * node_num) * crowdDensity
    yLen1 = math.sqrt(area1)
    area2 = round(.3 * node_num) * crowdDensity
    yLen2 = math.sqrt(area2)
    area3 = (node_num-round(.6 * node_num)-round(.3 * node_num)) * crowdDensity
    yLen3 = math.sqrt(area3)

    # randomly assign positions based on density
    initialPositions1 = assignFinalPosMarch((start_pos[0], start_pos[0]+street_len), (start_pos[1], start_pos[1]+yLen1), round(.6 * node_num), minDistance)
    initialPositions2 = assignFinalPosMarch((start_pos[0], start_pos[0]+street_len), (start_pos[1], start_pos[1]+yLen2), round(.3 * node_num), minDistance)
    initialPositions3 = assignFinalPosMarch((start_pos[0], start_pos[0]+street_len), (start_pos[1], start_pos[1]+yLen3), (node_num-round(.6 * node_num)-round(.3 * node_num)), minDistance)


    initialPositionsList = list(initialPositions1.values())
    initialPositionsList.extend(list(initialPositions2.values()))
    initialPositionsList.extend(list(initialPositions3.values()))
    ##### -----------------------------------------------------------------------------------------------------------------------
    ##### Once all nodes are in their start positions (or immediately, if this is the beginning of the simulation), 
    ##### we assign all nodes to move at the same direction (that of the street) and same speed for a set length of time.
    ##### -----------------------------------------------------------------------------------------------------------------------
    #randomly assigned starting positions from above
    initialPositions = np.array([list(x) for x in initialPositionsList])

    time = np.arange(seconds)
    positions = np.zeros((seconds, nodecount, 2))
    positions[0] = initialPositions

    # speed at which protestors will walk 
    # - https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7806575/
    # - article provides slow (0.82), usual (1.31), medium (1.47), fast (1.72), and maximal (1.62) walking pace 
    metersPerIter = 1.31
    # generate future positions given walking speed
    for t in range(1, seconds):
        for i in range(nodecount):
            noisedMetersPerIter = metersPerIter+random.uniform(-.5,.5)
            positions[t][i] = [positions[t - 1][i][0], positions[t - 1][i][1]+noisedMetersPerIter]
    
    if(np.size(marchProtestPositions) != 0):
        marchProtestPositions = np.concatenate((marchProtestPositions, positions), axis=1)
    else:
        marchProtestPositions = positions
#return array of march protest positions   
    return marchProtestPositions

#################################################################################################################################
#################################################################################################################################
### RANDOM
#################################################################################################################################
#################################################################################################################################

# -------------------------------------------------------------------------------------------------------------------------------
#   assignStartPos
#   - Assigns [protesterCount] number of protesters to random positions of at least [minDistance] away from eachother, within
#     the x,y plane represented by [xRange and yRange]
# -------------------------------------------------------------------------------------------------------------------------------
def assignStartPos(xRange, yRange, protesterCount):
    positions = {}
    # get lengths of plane
    xLen = xRange[1]-xRange[0]
    yLen = yRange[1]-yRange[0]
    # for each protester
    for i in range(protesterCount):
        # until you get a valid point, generate a new random point
        random_x, random_y = getRandomWithin(xRange[0], xRange[1], yRange[0], yRange[1])
        positions['p'+str(i)] = (random_x, random_y)
    return positions


# -------------------------------------------------------------------------------------------------------------------------------
#   getRandom
# - get protester positions for random waypoint model
# -------------------------------------------------------------------------------------------------------------------------------
def getRandom(start_pos, node_num, backgroundValue):
    
    randomProtestPositions = np.empty((0,0,0)) 
    
    #for each sim
    # density = average distance to nearest person
    #           - perhaps .5m for "very crowded", 1m for "reasonably crowded", 3m for "sparse"?
    # minDistance = min distance from nearest person
    #           - a person standing takes about 1.5 square feet just standing (~.5m)
    
    if(backgroundValue):
        crowdDensity = 10 #PARAMETER
    else:
        crowdDensity = 1 #PARAMETER
    
    minDistance = .5 #PARAMETER
    
    # the size of the space is calculated based off of protester count and the density 
    area = nodecount * crowdDensity
    yLen = math.sqrt(area)
    xLen = math.sqrt(area)
    # randomly assign positions based on density
    initialPositions = assignStartPos((start_pos[0], start_pos[0]+xLen), (start_pos[1], start_pos[1]+yLen), node_num)
    initialPositionsList = list(initialPositions.values())

    minSpeed = .5 #PARAMETER
    maxSpeed = 3 ##PARAMETER
    
    # seconds that march length lasts 
    #randomly assigned starting positions from above
    initialPositions = np.array([list(x) for x in initialPositionsList])

    #set pause and total tile
    time = np.arange(seconds)
    positions = np.zeros((seconds, node_num, 2))
    positions[0] = initialPositions
    minPause = 0 #PARAMETER
    maxPause = 50 #PARAMETER 

    #for each protester:
    for p in range(nodecount):
        currTime=0
        while currTime < seconds:
            # first, nodes pause
            nodePauseLen = round(random.uniform(minPause, maxPause))
            #nodePauseLen = 1
            # assign same position from start for duration of pause
            if (nodePauseLen+currTime >= seconds):
                iterations = seconds - currTime 
            else:
                iterations = nodePauseLen +1
            
            for i in range(currTime+1,currTime+iterations):
                positions[i][p] = positions[i-1][p]
            #then generate future positions
            currTime = currTime + nodePauseLen

            if currTime >= seconds:
                break

            # select random location
            randomPoint = getRandomWithin(start_pos[0], start_pos[0]+xLen, start_pos[1], start_pos[1]+xLen)
            # select speed 
    
            randomSpeed = getRandomSpeed(minSpeed, maxSpeed)
            # get time it would take to get to new random location
            distanceBetween = getDistanceFromPoint(randomPoint, (positions[currTime][p][0], positions[currTime][p][1]))
            timeToTraverse = math.ceil(distanceBetween/randomSpeed)
            stops = generatePointsBetween(positions[currTime][p], list(randomPoint), timeToTraverse)
            stopNum = 0
            if (timeToTraverse+currTime >= seconds):
                iterations = seconds - currTime
            else:
                iterations = timeToTraverse +1
            for t in range(iterations):
                positions[t+currTime][p] = stops[stopNum]
                stopNum+=1
            currTime = currTime + timeToTraverse  
    
    if(np.size(randomProtestPositions) != 0):
        randomProtestPositions = np.concatenate((randomProtestPositions, positions), axis=1)
    else:
        randomProtestPositions = positions
    #return array of random protest positions
    return randomProtestPositions       


#################################################################################################################################
#################################################################################################################################
### STATIC
#################################################################################################################################
#################################################################################################################################

def getStatic(start_pos, node_num):
    distApart = 1 #PARAMETER! (spacing)

    positions = []
    x_val = start_pos[0]
    y_val = start_pos[1]

    nodes_per_row = math.ceil(math.sqrt(node_num))
    
    for i in range(nodecount):
        positions.append([x_val, y_val])
        
        if (i + 1) % nodes_per_row == 0:
            y_val += distApart
            x_val = 0
        else:
            x_val += distApart

    staticProtestPositions = []

    for s in range(seconds):
        staticProtestPositions.append([])            
        for p in range(len(positions)):
            staticProtestPositions[s].append(positions[p])
    
    #return array of chain protest positions
    print(len(positions))
    return np.array(staticProtestPositions)


#################################################################################################################################
#################################################################################################################################
### ARP
#################################################################################################################################
#################################################################################################################################
def getARP(nodecount):
    arppositions = []
    arpsideCount = math.ceil(math.sqrt(nodecount))
    xArpDistApart = 7.0/arpsideCount
    yArpDistApart = 7.0/arpsideCount
    y_val = 0
    nodecurr=0
    for y in range(arpsideCount):
        x_val = 0
        for x in range(arpsideCount):
            if(nodecurr<nodecount):
                arppositions.append([x_val, y_val])
                x_val += xArpDistApart
                nodecurr+=1
        y_val += yArpDistApart
    return arppositions


#################################################################################################################################
#################################################################################################################################
### MAIN
#################################################################################################################################
#################################################################################################################################
def main():

    ##### ---------------------------------------------------------------------------------------------------------------------------
    ##### Get total simulation space
    ##### --------------------------------------------------------------------------------------------------------------------------
    xRange = (0,300)
    yRange = (0,300)

    ##### ---------------------------------------------------------------------------------------------------------------------------
    ##### Assign sub-simulation spaces & get protester positions
    ##### ---------------------------------------------------------------------------------------------------------------------------

    ##### STATIC
    if(runtype == "static"):
        positions = getStatic([0,0], nodecount)

    ##### RANDOM
    if(runtype == "random"):
        positions = getRandom([0,0], nodecount, False)

    ##### CHAIN
    if(runtype == "chain"):
        positions = getChain([0,0], nodecount)

    ##### GATHER
    if(runtype == "gather"):
        positions = getGather([0,0], nodecount)

    ##### MARCH
    if(runtype == "march"):
        positions = getMarch([0,0], nodecount)

    # #### BLOCKADE_1
    if(runtype == "blockade1"):
        positions = getBlockade1([0,0], nodecount)

    # ##### BLOCKADE_2
    if(runtype == "blockade2"):
        positions = getBlockade2([0,0], nodecount)

    ##### RANDOM_BACKGROUND
    if(runtype == "random_back"):
        positions = getRandom([0,0], nodecount, False)

    #ARP POSITIONS
    arppos = getARP(positions.shape[1])
    arpTime = math.ceil(nodecount * (nodecount-1) * .01 ) + 10
    
    finalpos = []
    for t in range(arpTime):
        finalpos.append(arppos)
    for p in range(positions.shape[0]):
        finalpos.append(list(positions[p]))

    positions = np.array(finalpos)
    print(positions.shape, nodecount, len(arppos))

    #FIGURE
    fig, ax = plt.subplots(figsize=(8, 8))
    scatter = ax.scatter(positions[0][:, 0], positions[0][:, 1], s=15)
    xAxisRange = [-10,300]
    yAxisRange = [-10,300]
    ax.set_xlim(xAxisRange)
    ax.set_ylim(yAxisRange) 

    def update(frame):
        scatter.set_offsets(positions[frame])
        return scatter,

    anim = animation.FuncAnimation(fig, update, frames=seconds, blit=True)
    #plt.show()

    animation_file = "anim_files/"+runtype+"/node"+str(positions.shape[1])+"/"+str(iter)+".mp4"
    if not os.path.exists("anim_files/"+runtype+"/node"+str(positions.shape[1])+"/"):
        # Create the directory
        os.makedirs("anim_files/"+runtype+"/node"+str(positions.shape[1])+"/")

    # writervideo = animation.FFMpegWriter(fps=60) 
    # anim.save(animation_file, writer=writervideo) 
    
    position_file = "position_files/"+runtype+"/node"+str(positions.shape[1])+"/"+str(iter)+".npy"
    trace_file = "trace_files/"+runtype+"/node"+str(positions.shape[1])+"/"+str(iter)+".txt"
    
    if not os.path.exists("position_files/"+runtype+"/node"+str(positions.shape[1])+"/"):
        # Create the directory
        os.makedirs("position_files/"+runtype+"/node"+str(positions.shape[1])+"/")

    if not os.path.exists("trace_files/"+runtype+"/node"+str(positions.shape[1])+"/"):
        # Create the directory
        os.makedirs("trace_files/"+runtype+"/node"+str(positions.shape[1])+"/")

    # generate trace log file
    # https://groups.google.com/g/ns-3-users/c/BDKWGB-pthE
    f = open(trace_file, "w")
    # set initial positions
    for s in range(len(positions)):
        for nodeNum in range(len(positions[0])):
            f.write("$node_("+str(nodeNum)+") set X_ "+str(positions[s][nodeNum][0])+ "\n")
            f.write("$node_("+str(nodeNum)+") set Y_ "+str(positions[s][nodeNum][1])+ "\n")
            if s < arpTime:
                speed = 0
            elif (s+1<len(positions)):
                speed = getDistanceFromPoint((positions[s][nodeNum][0], positions[s][nodeNum][1]), (positions[s+1][nodeNum][0], positions[s+1][nodeNum][1]))
            else:
                speed = 0
            f.write("$ns_ at "+str(s)+".0 \"$node_("+str(nodeNum)+") setdest "+str(positions[0][nodeNum][0])+" "+str(positions[0][nodeNum][1])+" "+str(speed)+" \""+ "\n")
    f.close()

    np.save(position_file, positions)

if __name__=="__main__": 
    main() 
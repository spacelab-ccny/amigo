#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include <algorithm>
#include <string>
#include <cmath>
#include <numeric>
#include <random>
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace ns3;
using namespace std;

/**********************************************************************************************************************************************
 * OVERVIEW
**********************************************************************************************************************************************
 * 
 * The routing protocol is made up of 3 parts, that occur repeatedly, one after the other: 
 * 
 * 1. Advertising Process
 *  - Every node in the simulation sends a beacon packet of size [N] bytes on an advertising channel, at 60 second intervals (at a random 
 *    time within the interval) [see SendAdvertisement_BeaconFrame].
 *  *  - When a node receives a beacon packet [see Receieve_BeaconFrame], if the node is a clique leader, it checks if the sender is its clique
 *    member, or is the leader of another clique. If the node is a clique member, it checks if the sender is its clique leader. If any of
 *    these conditions are met, it sends a probe request packet of size [N] to the sender node, to establish a connection [see 
 *    SendAdvertisement_ProbeRequestFrame].
 *  - When a node receives a probe request packet [see Receive_ProbeRequestFrame], it sends a probe response packet of size [N} to the 
 *    sender node. This completes the connection establishment process.
 * 
 * 2. Digest Exchange Process
 *  - The node that receives the probe response packet [see Receive_ProbeResponseFrame] responds with a bloom filter containing the message 
 *    IDs of all of the messages currently in the node's buffer [see Send_Bloom]. 
 *  - The node that receives this bloom filter [see Receive_Bloom], and searches for all messages in its own digest (an array of all 
 *    message IDs received). It then sends a message buffer to the sender node containing the elements in the diff (the messages currently 
 *    in the node's buffer, that it had not yet received) [see Send_MessagesFromBloom]. This completes the digest exchange process. 
 * 
 * 
**********************************************************************************************************************************************/

/**********************************************************************************************************************************************
 * GLOBAL VARS
**********************************************************************************************************************************************/

NodeContainer nodes; // container for all nodes
int nodeCount = 0; // number of nodes in sim total (read in & assigned from command line later!)

double simLen = 3600.0; // length of sim in seconds
double arpSendTime = 0.0; // current end time of ARP process as of runtime

std::vector<std::map<uint32_t, Ipv4Address>> NodeToIp; // map node IDs to IP addresses 
std::vector<std::map<Ipv4Address, uint32_t>> IpToNode; // map IP addresses to node IDs 

std::vector<std::vector<Ptr<Socket>>> advertiseSockets; // sockets for all nodes for all advertising channels
std::vector<std::vector<Ptr<Socket>>> dataSockets; // sockets for all nodes for all data exchange channels

//5 MB:
// n = 20000
// p = 0.00001 (1 in 100000)
// m = 479332 (58.51KiB)
// k = 17

const uint32_t bloomSize = 479332;
const uint32_t subset_size = 1450;
const uint32_t hashes = 17;

int maxBufferSize = 5000000; // (5MB) largest buffer that a node can have stored locally; value set from command line
const int messageSize = 250; // message data size of 250 bytes (approx tweet)
const int maxBufferSendSize = 1450; // largest buffer that can be sent in a single packet

/**********************************************************************************************************************************************
 * TRACKING VARS
**********************************************************************************************************************************************/

std::map<string, float> messageSentTime; // logs times messages were initially sent
std::map<string, float> messageReceivedTime; // logs times messages were received by intended receiver
std::map<uint32_t, uint32_t> messageSenderMap; // logs the initial sender ID for a given message
std::map<uint32_t, std::vector<uint32_t>> messageReceiverMap; // logs the initial recipient ID for a given message

uint32_t arpsent = 0; // tracks # of arp messages sent 
uint32_t arprecv = 0; // tracks # of arp messages received
uint32_t send_msgs = 0; // tracks # of message packets sent
uint32_t recv_msgs = 0; // tracks # of message packets received
uint32_t send_digs = 0; // tracks # of digest packets sent
uint32_t recv_digs = 0; // tracks # of digest packets received
uint32_t send_beacons = 0; // tracks # of beacon packets sent
uint32_t recv_beacons = 0; // tracks # of beacon packets received
uint32_t send_proberequest = 0; // tracks # of probe request packets sent
uint32_t recv_proberequest = 0; // tracks # of probe request packets received
uint32_t send_proberesponse = 0; // tracks # of probe response packets sent
uint32_t recv_proberesponse = 0; // tracks # of probe response packets received
uint32_t ageMessageDrops = 0; // logs the number of messages dropped from the buffers of nodes
uint32_t spaceMessageDrops = 0; // logs the number of messages dropped from the buffers of nodes

std::string packetFile;

void LogPacketSends(std::string file, std::string var_name){
    std::ofstream buff_file;
    buff_file.open (file,  std::ios::app);
    buff_file << Simulator::Now().GetSeconds() << "," << var_name << "\n";
    buff_file.close();
}

/**********************************************************************************************************************************************
 * CUSTOM PACKET HEADERS
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
// PacketTypeHeader
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Determines what type of packet it is
// 0 = beacon frame
// 1 = probe request frame
// 2 = probe response frame
// 3 = arp set up frame 
// 4 = digest
// 5 = message buffer
// --------------------------------------------------------------------------------------------------------------------------------------------
class PacketTypeHeader : public Header
{
public:
  // required for valid new header
  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;
  virtual uint32_t GetSerializedSize (void) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual void Print (std::ostream &os) const;
  // allow protocol-specific access to header data
  void SetData (uint32_t data) {
    m_data = data;
  }
  uint32_t GetData () const {
    return m_data;
  }
private:
  uint32_t m_data;
};
TypeId
PacketTypeHeader::GetTypeId (void)
{
  static TypeId tid = TypeId ("PacketTypeHeader")
    .SetParent<Header> ()
    .AddConstructor<PacketTypeHeader> ()
  ;
  return tid;
}
TypeId
PacketTypeHeader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
uint32_t 
PacketTypeHeader::GetSerializedSize (void) const
{
  return 6;
}
void 
PacketTypeHeader::Serialize (Buffer::Iterator start) const
{
  // The 2 byte-constant
  start.WriteU8 (0xfe);
  start.WriteU8 (0xef);
  // The data.
  start.WriteHtonU32 (m_data);
}
uint32_t 
PacketTypeHeader::Deserialize (Buffer::Iterator start)
{
  uint8_t tmp;
  tmp = start.ReadU8 ();
  NS_ASSERT (tmp == 0xfe);
  tmp = start.ReadU8 ();
  NS_ASSERT (tmp == 0xef);
  m_data = start.ReadNtohU32 ();
  return 6; // the number of bytes consumed.
}
void 
PacketTypeHeader::Print (std::ostream &os) const
{
  os << "data=" << m_data;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
// DigestHeader
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Determines what subset of digest is being sent/received
// - Range is dependent on digest size, which is dependent on buffer size
// --------------------------------------------------------------------------------------------------------------------------------------------
class DigestHeader : public Header
{
public:
  // required for valid new header
  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;
  virtual uint32_t GetSerializedSize (void) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual void Print (std::ostream &os) const;
  // allow protocol-specific access to header data
  void SetData (uint32_t data) {
    m_data = data;
  }
  uint32_t GetData () const {
    return m_data;
  }
private:
  uint32_t m_data;
};
TypeId
DigestHeader::GetTypeId (void)
{
  static TypeId tid = TypeId ("DigestHeader")
    .SetParent<Header> ()
    .AddConstructor<PacketTypeHeader> ()
  ;
  return tid;
}
TypeId
DigestHeader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}
uint32_t 
DigestHeader::GetSerializedSize (void) const
{
  return 6;
}
void 
DigestHeader::Serialize (Buffer::Iterator start) const
{
  // The 2 byte-constant
  start.WriteU8 (0xfe);
  start.WriteU8 (0xef);
  // The data.
  start.WriteHtonU32 (m_data);
}
uint32_t 
DigestHeader::Deserialize (Buffer::Iterator start)
{
  uint8_t tmp;
  tmp = start.ReadU8 ();
  NS_ASSERT (tmp == 0xfe);
  tmp = start.ReadU8 ();
  NS_ASSERT (tmp == 0xef);
  m_data = start.ReadNtohU32 ();
  return 6; // the number of bytes consumed.
}
void 
DigestHeader::Print (std::ostream &os) const
{
  os << "data=" << m_data;
}

/**********************************************************************************************************************************************
 * STRUCTS
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
//   BloomFilter
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Bloom filter containing messageIDs of all nodes in the message buffers
// --------------------------------------------------------------------------------------------------------------------------------------------
class BloomFilter {
public:
    BloomFilter(int hashCount) : hashCount(hashCount) {}
    //insert msgID in bloom filter
    std::vector<size_t> insertMsg(uint32_t mID){ 
        std::vector<size_t> hashVec;
        for (int i = 0; i < hashCount; ++i) {
            //get hash
            size_t hashValue = hash(mID, i);
            //push back hash values in hash array
            hashVec.push_back(hashValue);
            //add values for hashes to bit array
            bitArray[hashVec[i] % bloomSize] = true;
        }
        return hashVec;
    }
    //reassign bit array
    void insert(std::bitset<bloomSize> bf){
        bitArray = bf;
    }
    //check if msgID in bloom filter
    bool contains(uint32_t item) const {
        for (int i = 0; i < hashCount; ++i) {
            size_t hashValue = hash(item, i);
            if (!bitArray[hashValue % bloomSize]) {
                return false; 
            }
        }
        return true;
    }
    //clear
    void clear() {
        bitArray.reset();
    }
    //print message digest
    void print(){
        std::ostringstream oss;
        oss << "digest contents: [";
        for (size_t i = 0; i < bloomSize; ++i) {
            oss << bitArray[i];
            if (i != bloomSize - 1) {
                oss << ", ";
            }
        }
        oss << "]";
        NS_LOG_UNCOND(oss.str());
    }
    //return bloom filter
    std::bitset<bloomSize> getBf(){
        return bitArray;
    }
private:
    //hash function, different hashes based on the index
    size_t hash(uint32_t item, int seed) const {
        return item ^ (seed * 0x9e3779b9 + (seed << 6) + (seed >> 2));  //simple mixing item and seed
    }
    std::bitset<bloomSize> bitArray;
    int hashCount;
};

// --------------------------------------------------------------------------------------------------------------------------------------------
//   Message
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Message objects are for each message 
// - Specifically, stores: (1) Message ID, (2) Message Text, (3) Message Time To Live, (4) Message Recipients, and (5) Message Sender
// - Also includes serialization / deserialization methods
// --------------------------------------------------------------------------------------------------------------------------------------------
class Message{
    public:
      // message identifier (unique to each message)
      uint32_t messageID;
      // contents of message
      std::string messageText;
      // message time to live (when it should be evicted from message buffer)
      float messageTTL;
      // who is the message sender
      uint32_t sender; 
      // who are desired message recipients
      std::vector<uint32_t> recipients;
      //message hash (not serialized, but here so we don't have to recalculate!)
      std::vector<size_t> hashVec;
      //space
      uint32_t space;
      Message() : messageID(0), messageTTL(0), sender(0),recipients(), hashVec(){}
    //check if messages are equal by messageID (not secure, rethink for irl implementation)
    bool operator==(const Message& other) const {
        return this->getMessageID() == other.getMessageID();
    }
    //set hashvec
    void setHashVec(std::vector<size_t> hashVec){
        this->hashVec = hashVec;
    }
    std::vector<size_t> getHashVec(){
        return hashVec;
    }
    //return message ID
    uint32_t getMessageID() const {return messageID;}
    //return message text
    std::string getMessageText() const {return messageText;}
    //return message ttl
    float getMessageTTL() const {return messageTTL;}
    //return message recipients
    std::vector<uint32_t> getMessageRecipients() const {return recipients;}
    //return message sender
    uint32_t getMessageSender() const {return sender;}
    //message serialization method
    //message serialization method
    std::string Serialize() const {
        std::ostringstream oss;
        oss << messageID << ",";
        oss << messageText << ",";
        oss << messageTTL << ",";
        oss << sender << ",";
        for (const auto& recipient : recipients) {
            oss << recipient << ",";
        }
        oss << space;
        return oss.str();
    }
    //message deserialization method
   void Deserialize(const std::string& data) {
        std::istringstream iss(data);
        char delimiter;
        iss >> messageID >> delimiter;
        std::getline(iss, messageText, ',');
        iss >> messageTTL >> delimiter;
        iss >> sender >> delimiter;
        recipients.clear();
        uint32_t recipient;
        while (iss >> recipient >> delimiter) {
            recipients.push_back(recipient);
        }
        iss >> space;
    }
    //message serialization helper
    friend std::ostream& operator<<(std::ostream& os, const Message& obj) {
        os.write(reinterpret_cast<const char*>(&obj.messageID), sizeof(obj.messageID));
        os.write(reinterpret_cast<const char*>(&obj.messageTTL), sizeof(obj.messageTTL));
        os.write(reinterpret_cast<const char*>(&obj.sender), sizeof(obj.sender));
        uint32_t vectorSize = obj.recipients.size();
        os.write(reinterpret_cast<const char*>(&vectorSize), sizeof(vectorSize));
        //serialize each Message
        for (const uint32_t& ipv4 : obj.recipients) {
          os.write(reinterpret_cast<const char*>(&ipv4), sizeof(ipv4));
        }
        //serialize the string length and then the string itself
        uint32_t messageTextLength = obj.messageText.length();
        os.write(reinterpret_cast<const char*>(&messageTextLength), sizeof(messageTextLength));
        os.write(obj.messageText.c_str(), messageTextLength);
        return os;
        }
    //message deserialization helper
    friend std::istream& operator>>(std::istream& is, Message& obj) {
        is.read(reinterpret_cast<char*>(&obj.messageID), sizeof(obj.messageID));
        is.read(reinterpret_cast<char*>(&obj.messageTTL), sizeof(obj.messageTTL));
        is.read(reinterpret_cast<char*>(&obj.sender), sizeof(obj.sender));
        uint32_t vectorSize;
        is.read(reinterpret_cast<char*>(&vectorSize), sizeof(vectorSize));
        //deserialize each Message 
        obj.recipients.clear();
        for (uint32_t i = 0; i < vectorSize; ++i) {
            uint32_t ipv4;
            is.read(reinterpret_cast<char*>(&ipv4), sizeof(ipv4));
            obj.recipients.push_back(ipv4);
        }
        //deserialize the string length
        uint32_t messageTextLength;
        is.read(reinterpret_cast<char*>(&messageTextLength), sizeof(messageTextLength));
        //resize the string and read the string itself
        obj.messageText.resize(messageTextLength);
        is.read(&obj.messageText[0], messageTextLength);
        return is;
    }
};

// --------------------------------------------------------------------------------------------------------------------------------------------
//   SerializeMessages
// - Serialization function for message buffers
// --------------------------------------------------------------------------------------------------------------------------------------------
void SerializeMessages(const std::vector<Message>& messages, uint8_t* buffer, size_t bufferSize) {
    std::ostringstream oss;
    //serialize the size of the vector
    uint32_t vectorSize = messages.size();
    oss.write(reinterpret_cast<const char*>(&vectorSize), sizeof(vectorSize));
    //serialize each Message
    for (const Message& msg : messages) {
        oss << msg;
    }
    //convert the serialized data into a byte array
    std::string serializedString = oss.str();
    size_t dataSize = std::min(bufferSize, serializedString.size());
    std::memcpy(buffer, serializedString.c_str(), dataSize);
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   DeserializeMessages
// - Deserialization function for message buffers
// --------------------------------------------------------------------------------------------------------------------------------------------
std::vector<Message> DeserializeMessages(const uint8_t* buffer, size_t bufferSize) {
    std::string serializedString(reinterpret_cast<const char*>(buffer), bufferSize);
    std::istringstream iss(serializedString);
    //deserialize the size of the vector
    uint32_t vectorSize;
    iss.read(reinterpret_cast<char*>(&vectorSize), sizeof(vectorSize));
    //deserialize each Message 
    std::vector<Message> messages;
    for (uint32_t i = 0; i < vectorSize; ++i) {
        Message msg;
        iss >> msg;
        messages.push_back(msg);
    }
    return messages;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   NodeHandler
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Creates a nodehandler object so that each node can store some state for logging metrics
// - Tracks the content of and info about a node's message buffer
// --------------------------------------------------------------------------------------------------------------------------------------------
class NodeHandler
{
    private:
        //Message Buffer
        std::vector<Message> messageBuffer;
        //Message Digest
        BloomFilter messageDigest;
        //Map of Message Digests
        std::map<uint32_t,std::bitset<bloomSize>> recvdMessageDigests;
        std::map<uint32_t,uint32_t> recvDigestCounts;
        //Clique Info
        uint32_t cliqueLeader;
        std::vector<uint32_t> cliqueMembers;
    public:
        NodeHandler(): messageBuffer(), messageDigest(hashes), recvdMessageDigests(), recvDigestCounts(), cliqueLeader(0), cliqueMembers() {}
    
    //CLIQUES

    //assign clique leader for node
    void addCliqueLeader(uint32_t cliqueListval) {cliqueLeader = cliqueListval;}
    
    //get node's clique leader
    uint32_t getCliqueLeader() {return cliqueLeader;}
    
    //add node to clique
    void addCliqueMember(uint32_t cliqueMemberval) {cliqueMembers.push_back(cliqueMemberval);}
    
    //get clique members
    std::vector<uint32_t> getCliqueMembers() {return cliqueMembers;}
    
    //check if node is clique member
    bool isCliqueMember(uint32_t toCheck){
        auto it = std::find(cliqueMembers.begin(), cliqueMembers.end(), toCheck);
        if (it != cliqueMembers.end()) {
            return true;
        } 
        else {
            return false;
        }
    }

    //remove a clique member
    void removeCliqueMember(uint32_t cID){
      cliqueMembers.erase(std::remove_if(cliqueMembers.begin(), cliqueMembers.end(),[&cID](uint32_t c) { return c == cID; }), cliqueMembers.end());
    }
    
    //RECVD MESSAGE DIGESTS

    //increment digest for node
    void incrementDigestCount(uint32_t nodeID){
        auto& count = recvDigestCounts[nodeID];
        ++count;
    }

    //clear digest for node
    void clearDigestMetadata(uint32_t nodeID){
        if(recvdMessageDigests.find(nodeID) != recvdMessageDigests.end()){
            recvdMessageDigests.erase(nodeID);
        }
        if(recvDigestCounts.find(nodeID) != recvDigestCounts.end()){
            recvDigestCounts.erase(nodeID);
        }
    }

    //get digest counts for node
    int getDigestCount(uint32_t nodeID){return recvDigestCounts[nodeID];}

    //get message digest value from node handler
    std::map<uint32_t, std::bitset<bloomSize>> getRecvdMesasgeDigests(){return recvdMessageDigests;}

    //get message digest value from node handler for specific node
    std::bitset<bloomSize> getRecvdNodeMessageDigest(uint32_t nodeID){return recvdMessageDigests[nodeID];}

    //add new node to message digests
    void addRecvdNodeToDigest(uint32_t nodeID, std::bitset<bloomSize> bs){recvdMessageDigests[nodeID] = bs;}

    //clear digest for node
    void clearRecvdNodeDigest(uint32_t nodeID){
        if(isMessageInDigest(nodeID)){
            recvdMessageDigests.erase(nodeID);
        }
    }
    
    //MESSAGE DIGEST
    
    //get message digest value from node handler
    BloomFilter getMessageDigest(){return messageDigest;}
    
    //check if message is in the digest
    bool isMessageInDigest(uint32_t mID){return messageDigest.contains(mID);}
    
    //add message to the digest
    std::vector<size_t> addMessageToDigest(Message m){return messageDigest.insertMsg(m.getMessageID());}
    
    //clear message digest
    void clearMessageDigest(){messageDigest.clear();}

    //regenerate/update the digest
    void updateMessageDigest(){
        //iterate through messages
        clearMessageDigest();
        for (int i = 0; i < messageBuffer.size(); ++i) {
            std::vector<size_t> hashvec = addMessageToDigest(messageBuffer[i]);
            messageBuffer[i].setHashVec(hashvec);
        }
    }

    //print message digest
    void printMessageDigest(){messageDigest.print();}

    //MESSAGE BUFFER

    //get message buffer from node handler
    std::vector<Message> getMessageBuffer() {return messageBuffer;}
    
    //get message buffer item count
    int getMessageBufferItemCount(){return messageBuffer.size();}

    //get message from message buffer
    Message getMessageFromBuffer(const Message& m) {
        auto it = std::find_if(messageBuffer.begin(), messageBuffer.end(),
                [m](const Message& msg) { return msg.getMessageID() == m.getMessageID(); });
        if (it != messageBuffer.end()) {
            return *it;
        } 
        else {
            return Message();
        }
    }

    //check if message is already in message buffer
    bool messageAlreadyInBuffer(const Message& m){
        auto it = std::find_if(messageBuffer.begin(), messageBuffer.end(),
                            [m](const Message& msg) { return msg.getMessageID() == m.getMessageID(); });
        if (it != messageBuffer.end()) {
            return true;
        } 
        else {
            return false;
        }
    }

    //add message to message buffer
    void addToMessageBuffer(Message m){
        //if message not expired, and message text size ok, and message not already in buffer
        if(((m.getMessageTTL()+arpSendTime) >= Simulator::Now().GetSeconds()) 
            && (size(m.getMessageText()) <= messageSize) 
            && (!messageAlreadyInBuffer(m))) {
            //if message text size less than space remaining in the buffer
            if(size(m.getMessageText()) <= (maxBufferSize - (messageSize*messageBuffer.size()))){
                messageBuffer.push_back(m);
                addMessageToDigest(m);
            }
            //else send current and create new buffer
            else{
                while (size(m.getMessageText()) > (maxBufferSize - (250*messageBuffer.size()))){
                    bool removed = false;
                    int removed_idx = 0;
                    //while message not removed
                    while((!removed) && (removed_idx < messageBuffer.size())){
                        Message m = messageBuffer[removed_idx];
                        //if treekem message, continue
                        if(m.getMessageText().find("t") != std::string::npos){
                            removed_idx++;
                            continue;
                        }
                        //if not treekem message, remove
                        else{
                            //remove message from message buffer
                            messageBuffer.erase(messageBuffer.begin()+removed_idx);
                            spaceMessageDrops++;
                            LogPacketSends(packetFile, "Space Message Drops");
                            removed = true;
                            removed_idx++;
                            //update message digest
                            updateMessageDigest();
                        }
                    }
                    if(!removed){
                        //remove message from message buffer
                        messageBuffer.erase(messageBuffer.begin());
                        //update message digest
                        updateMessageDigest();
                    }
                }                
                //add message to message buffer
                messageBuffer.push_back(m);
                //add message to message digest
                addMessageToDigest(m);
            }
        }      
    }

    //update message buffer
    void updateMessageBuffer(double ttl){
        int removedCount = std::count_if(messageBuffer.begin(), messageBuffer.end(), 
                            [&ttl](const Message& m) { return (m.getMessageTTL() + arpSendTime) < ttl; });
        ageMessageDrops+=removedCount;
        LogPacketSends(packetFile, "Age Message Drops");
        //remove expired messages from buffer
        messageBuffer.erase(std::remove_if(messageBuffer.begin(), messageBuffer.end(),[&ttl](Message m) { return (m.getMessageTTL()+arpSendTime) < ttl; }), messageBuffer.end());
        //create new message digest
        //NS_LOG_UNCOND("update1");
        updateMessageDigest();
        //NS_LOG_UNCOND("update2");
    }

    //remove message from message buffer
    void removeFromMessageBuffer(uint32_t mID){
        //remove message from buffer
        messageBuffer.erase(std::remove_if(messageBuffer.begin(), messageBuffer.end(),[&mID](Message m) { return m.getMessageID() == mID; }), messageBuffer.end());
        //create new message digest
        updateMessageDigest();
    }

    //clear message buffer
    void clearBuffer() {
      messageBuffer.clear();
      clearMessageDigest();
    }
};

// NodeHandler Tracker!!!
std::vector<NodeHandler> nodeHandlerArray;

// --------------------------------------------------------------------------------------------------------------------------------------------
// Struct to store a message to be sent
// --------------------------------------------------------------------------------------------------------------------------------------------
struct ScheduleMessage{
    float sendTime;
    Message m;
};

/**********************************************************************************************************************************************
 * CLIQUE INFO
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
//   createCliques
// --------------------------------------------------------------------------------------------------------------------------------------------
void createCliques(std::string groupfile){
    // Open the file
    std::ifstream file(groupfile);
    if (!file.is_open()) {
        std::cerr << "Failed to open file." << std::endl;
        return;
    }
    // read the file line by line
    std::string line;
    while (getline(file, line)) {
        //NS_LOG_UNCOND("LINE: " << line);
        std::stringstream ss(line);
        char c;
        while (ss >> c) {
            if (c == '[') {
                int value;
                int leader = -1;
                bool is_leader = true;
                while (ss >> value) {
                    if(is_leader){
                        leader = value;
                        nodeHandlerArray[value].addCliqueLeader(leader);
                        is_leader = false;
                    }
                    else{
                        nodeHandlerArray[leader].addCliqueMember(value);
                        nodeHandlerArray[value].addCliqueLeader(leader);
                    }
                    if (ss >> c && c == ',') continue; // skip comma
                    else if (c == ']') break; // exit loop when closing bracket is found
                }
            }
        }
    }
    file.close();
}

// --------------------------------------------------------------------------------------------------------------------------------------------
// PrintNodeHandlerCliqueInfo
// --------------------------------------------------------------------------------------------------------------------------------------------
void PrintNodeHandlerCliqueInfo(){
  NS_LOG_UNCOND("--------------------------------------------------------------------------------------------------------------------------------------------");
  NS_LOG_UNCOND("clique info:");
  for(int i = 0; i < nodeCount; i++){
    uint32_t leader = nodeHandlerArray[i].getCliqueLeader();
    std::vector<uint32_t> members = nodeHandlerArray[i].getCliqueMembers();
      std::stringstream ss;
      ss<< "[";
      for (int element : members) {
          ss << element;
          ss << ",";
      }
      ss<<"]";
      std::string resultString = ss.str();
    NS_LOG_UNCOND("node: " << i << " leader: " << leader << " members: " << resultString);
  }
  NS_LOG_UNCOND("--------------------------------------------------------------------------------------------------------------------------------------------");
}

/**********************************************************************************************************************************************
 * DIGEST/BUFFER RUNTIME ACCESS FUNCTIONS
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
//   AddMessageToDigest
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: node ID of node to add message to digest, message ID of message to add to digest
// - Output: n/a
// - Function: adds message to node buffer, hashes message ID and adds to bloom filter (digest) 
//             associated w/the given node
// --------------------------------------------------------------------------------------------------------------------------------------------
void AddMessageToDigest(uint32_t nodeID, Message m){
    nodeHandlerArray[nodeID].addMessageToDigest(m);
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   UpdateMessageDigest
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: node ID of node digest to update
// - Output: n/a
// - Function: create new bloom filter (digest) for the given node
// --------------------------------------------------------------------------------------------------------------------------------------------
void UpdateMessageDigest(uint32_t nodeID){
    nodeHandlerArray[nodeID].updateMessageDigest();
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   IsMessageInDigest
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: node ID of node digest to check, message ID to check if in digest
// - Output: bool (true or false)
// - Function: check if bloom filter (digest) returns true for the given message ID
// --------------------------------------------------------------------------------------------------------------------------------------------
bool IsMessageInDigest(uint32_t nodeID, uint32_t mID){
    return nodeHandlerArray[nodeID].isMessageInDigest(mID);
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   ClearMessageDigest
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: node ID of node digest to empty
// - Output: n/a
// - Function: empty the bloom filter of the given node
// --------------------------------------------------------------------------------------------------------------------------------------------
void ClearMessageDigest(uint32_t nodeID){
    nodeHandlerArray[nodeID].clearMessageDigest();
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   GetMessageDigest
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: node ID of node digest to return
// - Output: node digest
// - Function: returns the current digest associated with the given node
// --------------------------------------------------------------------------------------------------------------------------------------------
BloomFilter GetMessageDigest(int nodeID){
    return nodeHandlerArray[nodeID].getMessageDigest();
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   AddMessageToBuffer
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: node ID of node digest to return, Message to add
// - Output: n/a
// - Function: adds message to node buffer of given nodeID
// --------------------------------------------------------------------------------------------------------------------------------------------
void AddMessageToBuffer(uint32_t nodeID, Message m){
    //add message to message buffer
     nodeHandlerArray[nodeID].addToMessageBuffer(m);
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   UpdateNodeBuffer
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: node ID of node buffer to update
// - Output: n/a
// - Function: removes messages from the buffer that have outdated TTLs
// --------------------------------------------------------------------------------------------------------------------------------------------
void UpdateNodeBuffer(uint32_t nodeNum){
    nodeHandlerArray[nodeNum].updateMessageBuffer(Simulator::Now().GetSeconds());
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   RemoveMessageFromBuffer
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: node ID of message buffer to remove message from, message ID of message to remove
// - Output: n/a
// - Function: removes the message with the given ID from message buffer of the given node
// --------------------------------------------------------------------------------------------------------------------------------------------
void RemoveMessageFromBuffer(uint32_t nodeID, uint32_t messageIDVal){
    nodeHandlerArray[nodeID].removeFromMessageBuffer(messageIDVal);
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   ClearBuffer
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: node ID of message buffer to clear
// - Output: n/a
// - Function: removes all messages from the message buffer of the given node
// --------------------------------------------------------------------------------------------------------------------------------------------
void ClearBuffer(uint32_t nodeID){
    nodeHandlerArray[nodeID].clearBuffer();
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   CheckBuffer
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: node ID of message buffer to check, message ID val to check, message text val to check, message TTL val to check, 
//          message sender val to check, message recipients val to check
// - Output: bool (t/f whether message is in buffer)
// - Function: checks if message with the given ID, text, and TTL values exists in the given node's message buffer
// --------------------------------------------------------------------------------------------------------------------------------------------
bool MessageAlreadyInBuffer(uint32_t nodeID, uint32_t messageIDVal, std::string messageTextVal, float messageTTLVal, uint32_t messageSenderVal, std::vector<uint32_t> messageRecipientsVal){
    //create message
    Message m;
    m.messageID = messageIDVal;
    m.messageText = messageTextVal;
    m.messageTTL = messageTTLVal;
    m.sender = messageSenderVal;
    m.recipients = messageRecipientsVal;
    //check if message exists
    Message m_2 = nodeHandlerArray[nodeID].getMessageFromBuffer(m);
    if (m_2.getMessageID() >= 0){
        return true;
    }
    else{
        return false;
    }
}

/**********************************************************************************************************************************************
 * ARP CONFIGURATION
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
//   SendARPMessage
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on, IP to send to
// - Output: n/a
// - Function: send arp message on given socket to remote IP
// --------------------------------------------------------------------------------------------------------------------------------------------
void SendARPMessage(Ptr<Socket> socket, Ipv4Address remoteIP) {
    Ptr<Packet> packet = Create<Packet> (1);
    //ad header
    PacketTypeHeader arpHeader;
    arpHeader.SetData (3);
    packet->AddHeader (arpHeader);
    //send packet
    InetSocketAddress remoteAddress = InetSocketAddress(remoteIP, 80);
    socket->SendTo(packet, 0, remoteAddress);
    arpsent++;
    return;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   GetNodeFromMacAddress
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: mac address, node container of all nodes
// - Output: nodeID
// - Function: given Mac Address, determine the associated node ID; if no node ID found, return -1
// --------------------------------------------------------------------------------------------------------------------------------------------
uint32_t GetNodeFromMacAddress(Mac48Address mac, NodeContainer nodes) {
    for (NodeContainer::Iterator it = nodes.Begin(); it != nodes.End(); ++it) {
        Ptr<Node> node = *it;
        for (uint32_t i = 0; i < node->GetNDevices(); ++i) {
            Ptr<NetDevice> dev = node->GetDevice(i);
            Ptr<WifiNetDevice> wifiDev = DynamicCast<WifiNetDevice>(dev);
            if (wifiDev && wifiDev->GetAddress() == mac){
                return node->GetId();
            }
        }
    }
    return -1;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   ReceivePromiscDevice
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: device, packet, protocol, address, address2, packet type to determine info about packet
// - Output: returns true if success
// - Function: receiver node processes layer 2 packet received via the given NetDevice, and logs if ARP packet, etc.
// --------------------------------------------------------------------------------------------------------------------------------------------
bool ReceivePromiscDevice(Ptr<NetDevice> d, Ptr<const Packet> p, uint16_t protocol, const ns3::Address &a, const ns3::Address &a2, ns3::NetDevice::PacketType pt)
{
//   bool isARP = false; 
  //get packet data
  uint8_t* data = new uint8_t[p->GetSize()];
  p->CopyData(data, p->GetSize());
  std::stringstream ss;
  for (uint32_t i = 0; i < p->GetSize(); ++i) {
      ss << std::hex << (int)data[i] << " ";
  }
  ss << std::endl;

  if (protocol == 0x0800) { // IPv4 
        // isARP = false;
        NS_LOG_UNCOND("Received IPv4 packet");
    } 
  else if (protocol == 0x0806) { // ARP
        NS_LOG_UNCOND(d->GetNode()->GetId() << " Received ARP packet " << Simulator::Now());
        // isARP = true;
    } 
  else {
        NS_LOG_UNCOND("Received unknown packet");
  }

  std::string rec = "";
  if(pt == 1){
    rec = "intended recipient";
  } 
  else if(pt == 4){
    rec = "not intended recipient";
  }
//   if(isARP){
//       NS_LOG_UNCOND("-------------------------------------------------------------------------------------\n"<<
//                     "Packet Received At Time : " << Simulator::Now().GetSeconds() << "\n" <<
//                     "Sender Layer 3 Addr : " << GetNodeFromMacAddress(Mac48Address::ConvertFrom(a), nodes)  << "\n" << 
//                     "Sender Layer 2 Addr: : " << a << "\n" <<
//                     "Receiver Layer 2 Addr : " << a2 << "\n" <<
//                     "Receiver Layer 3 Addr : " << d->GetNode()->GetId() << "\n" <<
//                     "INTERNAL PACKET INFO : \n" <<
//                     "Packet Size " << p->GetSize() << "\n" << 
//                     "Is Recipient? " << rec << "\n" << 
//                     "Packet data:" << "\n" << ss.str() <<
//                     "-------------------------------------------------------------------------------------\n");
//   }
    return true;
}

/**********************************************************************************************************************************************
 * MESSAGE EXCHANGE PROCESS 
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
//   SendBuffer
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on (socket), IP address to send to (sender), vector of messages to send (toSend), and nodeID of local node
// - Output: n/a
// - Function: send messages containing buffer of requested messages 
// --------------------------------------------------------------------------------------------------------------------------------------------
void SendBuffer(Ptr<Socket> socket, Ipv4Address sender, const std::vector<Message>& miniMessageBuffer, uint32_t nodeID) {
    
    //serialize messages
    size_t bufferSize = (messageSize+100) * miniMessageBuffer.size();
    std::vector<uint8_t> serializedBuffer(bufferSize);
    SerializeMessages(miniMessageBuffer, serializedBuffer.data(), bufferSize);

    Ptr<Packet> packet = Create<Packet>(serializedBuffer.data(), bufferSize);

    //add header
    PacketTypeHeader adHeader;
    adHeader.SetData(5);
    packet->AddHeader(adHeader);

    //send packet
    InetSocketAddress remoteAddress = InetSocketAddress(sender, 80);
    socket->SendTo(packet, 0, remoteAddress);

    //track the send time for each message
    for (const auto& mini : miniMessageBuffer) {
        std::string sentIndex = std::to_string(mini.messageID) + "." + std::to_string(nodeID);
        if (messageSentTime.find(sentIndex) == messageSentTime.end()) {
            messageSentTime[sentIndex] = Simulator::Now().GetSeconds();
        }
    }

    //logging
    send_msgs++;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   Send_MessagesFromRequest
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on (socket), IP address to send to (sender), channel to send on (c) , and vector of messages to send (toSend)
// - Output: n/a
// - Function: send buffer of messages containing buffer of requested messages 
// --------------------------------------------------------------------------------------------------------------------------------------------
void Send_MessagesFromRequest(Ptr<Socket> socket, Ipv4Address sender, int c, const std::vector<Message>& toSend) {
    uint32_t nodeID = socket->GetNode()->GetId();
    UpdateNodeBuffer(nodeID);

    std::vector<Message> miniMessageBuffer;
    miniMessageBuffer.reserve(toSend.size()); //avoid dynamic resize

    size_t currentBufferSize = 0;

    for (const auto& m : toSend) {
        if (!nodeHandlerArray[nodeID].messageAlreadyInBuffer(m)) {
            continue;  //skip if <essage isn't in the buffer
        }

        Message msg = nodeHandlerArray[nodeID].getMessageFromBuffer(m);
        size_t msgSize = messageSize + 50;

        //if adding this message would exceed the buffer size, send the current buffer first
        if (currentBufferSize + msgSize > maxBufferSendSize) {
            SendBuffer(socket, sender, miniMessageBuffer, nodeID);
            miniMessageBuffer.clear();  //clear the buffer
            currentBufferSize = 0;  //reset buffer size
        }

        //add message to the buffer & update current buffer size
        miniMessageBuffer.push_back(msg);
        currentBufferSize += msgSize;
    }

    //send remaining messages (if any)
    if (!miniMessageBuffer.empty()) {
        SendBuffer(socket, sender, miniMessageBuffer, nodeID);
    }

}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   Send_IndivMessagesFromRequest
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on (socket), IP address to send to (sender), vector of messages to send (toSend)
// - Output: n/a
// - Function: send individual messages from vector of requested messages 
// --------------------------------------------------------------------------------------------------------------------------------------------
//TODO

// --------------------------------------------------------------------------------------------------------------------------------------------
//   ReceiveMessageBuffer
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on (socket), packet containing message buffer content
// - Output: n/a
// - Function: when a node receives a message buffer packet, it deserializes the messages and adds them to its own buffer
// --------------------------------------------------------------------------------------------------------------------------------------------
void Receive_MessageBuffer(Ptr<Socket> socket, Ptr<Packet> packet) {
    //get nodeID
    uint32_t nodeID = socket->GetNode()->GetId();

    //copy packet data into buffer
    std::vector<uint8_t> buffer(packet->GetSize());
    packet->CopyData(buffer.data(), buffer.size());

    //deserilaize messages from buffer
    std::vector<Message> deserializedMessages = DeserializeMessages(buffer.data(), buffer.size());

    //add messages to local message buffer
    for (const Message& msg : deserializedMessages) {
        std::string recIndex = std::to_string(msg.messageID) + "." + std::to_string(nodeID);

        //if node is recipient
        if (std::find(msg.recipients.begin(), msg.recipients.end(), nodeID) != msg.recipients.end()) {
            //log receipt, add to buffer
            if (messageReceivedTime.find(recIndex) == messageReceivedTime.end()) {
                messageReceivedTime[recIndex] = Simulator::Now().GetSeconds();
            }
            AddMessageToBuffer(nodeID, msg);
        }
        //node is not a recipient, add to buffer
        else {
            AddMessageToBuffer(nodeID, msg);
        }
    }
}

/**********************************************************************************************************************************************
 * DIGEST EXCHANGE
**********************************************************************************************************************************************/
// --------------------------------------------------------------------------------------------------------------------------------------------
//   ClearDigestMetadata
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: local nodeID to clear metadata on, sendID to clear local stored metadata for
// - Output: n/a
// - Function: clears the bloom filter and chunk counter for the given node and sendID
// --------------------------------------------------------------------------------------------------------------------------------------------
void ClearDigestMetadata(uint32_t nodeID, uint32_t sendID){
    nodeHandlerArray[nodeID].clearDigestMetadata(sendID);
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   GetDigestFromBuffer
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: buffer of int8_t values, size of buffer, digest ID of given chunk
// - Output: bitset equivalent of buffer
// - Function: converts the buffer subset into a bitset subset and returns the bitset
// --------------------------------------------------------------------------------------------------------------------------------------------
std::bitset<bloomSize> GetDigestFromBuffer(uint8_t *buffer, size_t bufferSize, uint32_t digID){
    std::bitset<bloomSize> bitset;
    for (size_t i = 0; i < bufferSize; ++i) {
        uint8_t byteValue = buffer[i];
        for (size_t bitOffset = 0; bitOffset < 8; ++bitOffset) {
            if (i * 8 + bitOffset < bloomSize) {
                bool bitValue = byteValue & (1 << bitOffset);
                bitset[(digID * subset_size) + i * 8 + bitOffset] = bitValue;
            }
        }
    }
    return bitset;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   SendDigestChunks
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on, nodeID of local node, remote IP address
// - Output: n/a
// - Function: sends the message digest of the local node to the remote node
// --------------------------------------------------------------------------------------------------------------------------------------------
void SendDigestChunks(Ptr<Socket> socket, uint32_t nodeID, Ipv4Address remoteIP){

    //get message digest
    std::bitset<bloomSize> bitset = nodeHandlerArray[nodeID].getMessageDigest().getBf();

    //make buffer
    const size_t bufferSize = (bloomSize + 7) / 8; // round up
    uint8_t buffer[bufferSize]; 

    //extract bytes from the bitset
    for (size_t i = 0; i < bufferSize; ++i) {
        uint8_t byteValue = 0;
        for (size_t bitOffset = 0; bitOffset < 8; ++bitOffset) {
            if (i * 8 + bitOffset < bloomSize) {
                bool bitValue = bitset[i * 8 + bitOffset];
                byteValue |= (bitValue << bitOffset);
            }
        }
        buffer[i] = byteValue;
    }

    int iters = (bufferSize + subset_size - 1) / subset_size;

    //sub buffers
    for (size_t i = 0; i < iters; ++i) {
        
        //create subbuffer
        uint8_t subBuffer[subset_size];
        for (size_t j = 0; j < subset_size; ++j) {
            if ((i*subset_size) + j < bufferSize) {
                subBuffer[j] = buffer[(i*subset_size) + j];
            }
        }

        //create a packet, add byte array
        Ptr<Packet> packet = Create<Packet>(subBuffer, subset_size);

        //add digest header
        DigestHeader digHeader;
        digHeader.SetData(i);
        packet->AddHeader(digHeader);

        //add packet type header
        PacketTypeHeader adHeader;
        adHeader.SetData(4);
        packet->AddHeader(adHeader);

        //send the packet
        InetSocketAddress remoteAddress = InetSocketAddress(remoteIP, 80);

        socket->SendTo(packet, 0, remoteAddress);
        send_digs++;
    }
    
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   GetDiffMessagesFromBloom
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: local node ID, and ID of sender node to retrieve and compare locally stored bloom filter of
// - Output: vector of messages that sender node does not have, that local node does have
// - Function: compares local node messages with the bloom filter of the sender node, and returns messages the sender node does not have
// --------------------------------------------------------------------------------------------------------------------------------------------
std::vector<Message> GetDiffMessagesFromBloom(uint32_t nodeID, uint32_t sendID){
    std::vector<Message> diffedMessages;
    std::vector<Message> localMessages = nodeHandlerArray[nodeID].getMessageBuffer();
    // see if any messages to send (compare local messages hashes with sent hashes)
    BloomFilter compareBloom(hashes);
    compareBloom.insert(nodeHandlerArray[nodeID].getRecvdNodeMessageDigest(sendID));
    //NS_LOG_UNCOND("get bf: " << compareBloom.getBf());
    for(const Message& m : localMessages){
        //create bloom
        if(!compareBloom.contains(m.getMessageID())){
            diffedMessages.push_back(m);
        }
    }
    std::vector<uint32_t> difIDs;
    for(const Message& m : diffedMessages){
        difIDs.push_back(m.getMessageID());
    }
    // if(nodeID <=10){
    //     if(sendID <=10){
    //         //NS_LOG_UNCOND(Simulator::Now().GetSeconds() << "node: " << nodeID << "and sendID: " << sendID << " diffed messages (len" << difIDs.size() << "): ");
    //         for (uint32_t num : difIDs) {
    //             std::cout << num << " ";
    //         }
    //         std::cout << std::endl;

    //     }
    // }
    
    return diffedMessages;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   SendMessages
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: local node ID, ID of node to send to, socket to send on, IP address to send to, channel to send on
// - Output: n/a
// - Function: sends messages to the given node based upon the local understanding of the sender node's bloom filter, and clears 
//             the digest metadata for the given node
// --------------------------------------------------------------------------------------------------------------------------------------------
void SendMessages(uint32_t nodeID, uint32_t sendID, Ptr<Socket> socket, Ipv4Address sender, int channelID){
    std::vector<Message> messagesToSend = GetDiffMessagesFromBloom(nodeID, sendID);
    Send_MessagesFromRequest(socket, sender, channelID, messagesToSend);
    ClearDigestMetadata(nodeID, sendID);
    return;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   Receive_DigestChunk
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on, IP address of sender, packet containing digest chunk, channel to send on
// - Output: n/a
// - Function: receives a digest chunk from a remote node, and updates the local understanding of sender's digest with the received chunk
// --------------------------------------------------------------------------------------------------------------------------------------------
void Receive_DigestChunk(Ptr<Socket> socket, Ipv4Address sender, Ptr<Packet> packet, int channelID){
    //remove header
    DigestHeader digHeader;
    packet->RemoveHeader (digHeader);
    uint32_t digID = digHeader.GetData ();
    //deserialize packet
    uint8_t buffer[packet->GetSize()];
    packet->CopyData(buffer, packet->GetSize());
    GetDigestFromBuffer(buffer, packet->GetSize(), digID);
    uint32_t nodeID = socket->GetNode()->GetId();
    uint32_t sendID = IpToNode[channelID][sender];
    //add to digest of node
    std::bitset<bloomSize> old_bs = nodeHandlerArray[nodeID].getRecvdNodeMessageDigest(sendID);
    std::bitset<bloomSize> sent_bs = GetDigestFromBuffer(buffer, packet->GetSize(), digID);
    std::bitset<bloomSize> new_bs = old_bs ^ sent_bs;
    nodeHandlerArray[nodeID].addRecvdNodeToDigest(sendID, new_bs);
    nodeHandlerArray[nodeID].incrementDigestCount(sendID);
    //TODO -- confirm this is what we want
    if(nodeHandlerArray[nodeID].getDigestCount(sendID) == 1){
        Simulator::Schedule(Seconds(15), &SendMessages, nodeID, sendID, socket, sender, channelID);
    }
}

/**********************************************************************************************************************************************
 * ADVERTISEMENT PACKETS
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
//   SendAdvertisement_BeaconFrame
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on, channel to send on, node to send to
// - Output: n/a
// - Function: send beacon frame as broadcast (to all nodes, on 255.255.255.255)
// --------------------------------------------------------------------------------------------------------------------------------------------
void SendAdvertisement_BeaconFrame(Ptr<Socket> socket, int senderChannel, uint32_t senderNode) {
    Ptr<Packet> packet = Create<Packet> (155);
    //set ad header
    PacketTypeHeader adHeader;
    adHeader.SetData (0);
    packet->AddHeader (adHeader);
    InetSocketAddress remoteAddress = InetSocketAddress(Ipv4Address("255.255.255.255"), 80);
    socket->SendTo(packet, 0, remoteAddress);
    send_beacons++;
    return;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   SendAdvertisement_ProbeRequestFrame
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on, channel sent on, node to send to, IP address to send to
// - Output: n/a
// - Function: send probe request frame (in response to beacon frame)
// --------------------------------------------------------------------------------------------------------------------------------------------
void SendAdvertisement_ProbeRequestFrame(Ptr<Socket> socket, int senderChannel, uint32_t senderNode, Ipv4Address remoteIP){
    Ptr<Packet> packet = Create<Packet> (124);
    //set ad header
    PacketTypeHeader adHeader;
    adHeader.SetData (1);
    packet->AddHeader (adHeader);
    InetSocketAddress remoteAddress = InetSocketAddress(remoteIP, 80);
    socket->SendTo(packet, 0, remoteAddress);
    send_proberequest++;
    return;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   SendAdvertisement_ProbeResponseFrame
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on, channel to send on, node to send to, IP address to send to
// - Output: n/a
// - Function: send probe response frame (in response to probe request frame)
// --------------------------------------------------------------------------------------------------------------------------------------------
void SendAdvertisement_ProbeResponseFrame(Ptr<Socket> socket, int senderChannel, uint32_t senderNode, Ipv4Address remoteIP){
    Ptr<Packet> packet = Create<Packet> (199);
    //set ad header
    PacketTypeHeader adHeader;
    adHeader.SetData (2);
    packet->AddHeader (adHeader);
    InetSocketAddress remoteAddress = InetSocketAddress(remoteIP, 80);
    socket->SendTo(packet, 0, remoteAddress);
    send_proberesponse++;
    return;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   Receive_BeaconFrame
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on, IP address to send to, packet containing beacon frame, channel to send on
// - Output: n/a
// - Function: recieve beacon frame; if clique leader, responds to only clique members; if clique member, responds to only clique leader
// --------------------------------------------------------------------------------------------------------------------------------------------
void Receive_BeaconFrame(Ptr<Socket> socket, Ipv4Address sender, Ptr<Packet> packet, int c) {
    uint32_t nodeID = socket->GetNode()->GetId();
    uint32_t sendID = IpToNode[c][sender];
    
    // if you're not clique leader
    if (nodeHandlerArray[nodeID].getCliqueLeader() != nodeID){
      //check if sender node is your clique leader
      if (nodeHandlerArray[nodeID].getCliqueLeader() == sendID){
        SendAdvertisement_ProbeRequestFrame(socket, c, nodeID, sender);
      }
    }

    //if you are clique leader
    else{
      std::vector<uint32_t> members = nodeHandlerArray[nodeID].getCliqueMembers();  
      //if sender node is its clique leader
      if(std::find(members.begin(), members.end(), sendID) != members.end()){
        SendAdvertisement_ProbeRequestFrame(socket, c, nodeID, sender);
      }
    }
    //OTHERWISE, is member of another clique, and dont want to exchange further messages
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   Receive_ProbeRequestFrame
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on, IP address to send to, packet containing beacon frame, channel to send on
// - Output: n/a
// - Function: reciever probe request frame
// --------------------------------------------------------------------------------------------------------------------------------------------
void Receive_ProbeRequestFrame(Ptr<Socket> socket, Ipv4Address sender, Ptr<Packet> packet, int c) {
    uint32_t nodeID = socket->GetNode()->GetId();
    //uint32_t sendID = IpToNode[c][sender];
    SendAdvertisement_ProbeResponseFrame(socket, c, nodeID, sender);
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   Receive_ProbeResponseFrame
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to send on, IP address to send to, packet containing beacon frame, channel to send on
// - Output: n/a
// - Function: reciever probe response frame
// --------------------------------------------------------------------------------------------------------------------------------------------
void Receive_ProbeResponseFrame(Ptr<Socket> socket, Ipv4Address sender, Ptr<Packet> packet, int c){
    uint32_t nodeID = socket->GetNode()->GetId();
    //get new channel
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> channel_dist(0, 2);
    int channel = channel_dist(gen);
    //get new sender IP
    uint32_t sendID = IpToNode[c][sender];
    Ipv4Address sendIP = NodeToIp[channel+3][sendID];
    //send digest
    SendDigestChunks(dataSockets[channel][nodeID], nodeID, sendIP);
}

/**********************************************************************************************************************************************
 * RECV PACKET
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
//   ReceivePacket
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: socket to receive packet on
// - Output: n/a
// - Function: when a packet is received, determine the packet type, and take appropriate action accordingly 
// --------------------------------------------------------------------------------------------------------------------------------------------
void ReceivePacket(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;
    //when packet is received
    while ((packet = socket->RecvFrom(from))) {
        Ipv4Address sender = InetSocketAddress::ConvertFrom(from).GetIpv4();
        //get ad header
        PacketTypeHeader adHeader;
        packet->RemoveHeader (adHeader);
        uint32_t adID = adHeader.GetData ();
        int channelID = -1;
        for(int c=0; c<6; c++){
          std::map<Ipv4Address, uint32_t> mapcheck = IpToNode[c];
          if(mapcheck.count(sender) > 0){
            channelID = c;
            break;
          }
        }
        //beacon message
        if(adID == 0){
            recv_beacons++;
            Receive_BeaconFrame(socket, sender, packet, channelID);
        }
        //probe request
        else if(adID == 1){
            recv_proberequest++;
            Receive_ProbeRequestFrame(socket, sender, packet, channelID); 
        }
        //probe response
        else if(adID == 2){
            recv_proberesponse++;
            Receive_ProbeResponseFrame(socket, sender, packet, channelID); 
        }
        //arp
        else if(adID == 3){
            arprecv++;
        }
        //receive buffer contents
        else if(adID == 4){
            //NS_LOG_UNCOND("Received Digest Chunk");
            recv_digs++;
            Receive_DigestChunk(socket, sender, packet, channelID);
        }
        //receive messages
        else if(adID == 5){
            //NS_LOG_UNCOND("Received Message Buffer");
            recv_msgs++;
            Receive_MessageBuffer(socket, packet);
        }     
    }
}

/**********************************************************************************************************************************************
 * CHANNEL & DEVICE CONFIGURATION
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
//   MapIPAddresses
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: devices in simulation, channel #, total # of nodes
// - Output: n/a
// - Function: maps IP addresses to node IDs and vice versa for every node on every channel;
//             assigns all IP addresses for given node type (i.e. data1, data2, etc.)
// --------------------------------------------------------------------------------------------------------------------------------------------
void MapIPAddresses(Ipv4InterfaceContainer devices, int channel, int nodeTotal){
  std::map<uint32_t, Ipv4Address> nodetoip;
  std::map<Ipv4Address, uint32_t> iptonode;
  for (int i = 0; i < nodeTotal; ++i) {
    Ipv4Address addr = devices.GetAddress(i);
    nodetoip[i] = addr;
    iptonode[addr] = i;
  }
  NodeToIp.push_back(nodetoip);
  IpToNode.push_back(iptonode);
}

/**********************************************************************************************************************************************
 * LOGGING & TESTING METHODS
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
//   LogTime
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: string of current time
// - Output: n/a
// - Function: logs current real and simulation times
// --------------------------------------------------------------------------------------------------------------------------------------------
void LogTime(std::string log){
    std::time_t currentTime = std::time(nullptr);
    std::string timeString = std::ctime(&currentTime);
    NS_LOG_UNCOND("Sim Time: " << log << " Real Time: " << timeString);
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   LogMessage
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: message string to log
// - Output: n/a
// - Function: log given message
// --------------------------------------------------------------------------------------------------------------------------------------------
void LogMessage(std::string msg){
    NS_LOG_UNCOND(msg);
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   SplitString
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: string to split
// - Output: vector of string substrings
// - Function: split the string at the "." character
// --------------------------------------------------------------------------------------------------------------------------------------------
std::vector<std::string> SplitString(std::string str){
    std::istringstream iss(str);
    std::vector<std::string> tokens;
    std::string token;
    // Iterate over the string and split by "."
    while (std::getline(iss, token, '.')) {
        tokens.push_back(token);
    }
    return tokens;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
//   PrintIPAddresses
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: devices
// - Output: n/a
// - Function: prints all IP addresses for given node type (i.e. data1, data2, etc.)
// --------------------------------------------------------------------------------------------------------------------------------------------
void PrintIPAddresses(Ipv4InterfaceContainer devices, int nodeTotal){
  NS_LOG_UNCOND("IP Addresses For Nodes");
  for (uint32_t i = 0; i < nodeTotal; ++i) {
    Ipv4Address addr = devices.GetAddress(i);
    NS_LOG_UNCOND("Node " << i << ": " << addr);
  }
}

/**********************************************************************************************************************************************
 * MESSAGE METADATA & SCHEDULING
**********************************************************************************************************************************************/

// --------------------------------------------------------------------------------------------------------------------------------------------
//   ReadGroupsFile
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: filepath to groups file
// - Output: vector of vectors (groups and group members)
// - Function: given file of groups, read the groups into a vector of vectors
// --------------------------------------------------------------------------------------------------------------------------------------------
std::vector<std::vector<int>> ReadGroupsFile(std::string groupfile){
  std::vector<std::vector<int>> arrays;
  // Open the file
    std::ifstream file(groupfile);
    if (!file.is_open()) {
        std::cerr << "Failed to open file." << std::endl;
        return arrays;
    }
    // read the file line by line
    std::string line;
    while (getline(file, line)) {
        std::stringstream ss(line);
        char c;
        std::vector<int> array;   
        while (ss >> c) {
            if (c == '[') {
                int value;
                while (ss >> value) {
                    array.push_back(value);
                    if (ss >> c && c == ',') continue; // skip comma
                    else if (c == ']') break; // exit loop when closing bracket is found
                }
            }
        }
        arrays.push_back(array);
    }
    file.close();
    return arrays;
}

// --------------------------------------------------------------------------------------------------------------------------------------------
// GetTrafficModel
// --------------------------------------------------------------------------------------------------------------------------------------------
// - Input: filepath to traffic model file
// - Output: vector of ScheduleMessages (messages and times they should be sent)
// - Function: gets traffic model from providedfile
// --------------------------------------------------------------------------------------------------------------------------------------------
std::vector<ScheduleMessage> GetTrafficModel(std::string filePath){ 
    //open the file
    std::ifstream inputFile(filePath);
    if (!inputFile.is_open()) {
        std::cerr << "Error opening file: " << filePath << std::endl;
    }
    //read file line by line
    std::string line;
    std::vector<ScheduleMessage> messagesToSend;
    if (std::getline(inputFile, line)) {
        std::cout << "\n" << std::endl;
    }
    while (std::getline(inputFile, line)) {
        Message m;
        //use a stringstream to split the line into tab-separated values
        std::istringstream iss(line);
        std::string token;
        //first, messageID
        std::getline(iss, token, '\t');
        m.messageID = std::stoi(token);
        //second, messagesender
        std::getline(iss, token, '\t');
        m.sender = std::stoi(token);
        //third get recipients
        std::getline(iss, token, '\t');
        token.erase(std::remove(token.begin(), token.end(), '['), token.end());
        token.erase(std::remove(token.begin(), token.end(), ']'), token.end());
        //create stringstream from the modified string
        std::istringstream iss2(token);
        //parse the values and store them in a vector
        std::vector<int> values;
        uint32_t value;
        std::vector<uint32_t> recipients;
        while (iss2 >> value) {
          recipients.push_back(value);
            //check for the comma and ignore it
            if (iss2.peek() == ',') {
                iss2.ignore();
            }
        }
        m.recipients = recipients;
        //fourth, get send time
        std::getline(iss, token, '\t');
        float sendtime = std::stof(token);
        //fifth, get TTL
        std::getline(iss, token, '\t');
        m.messageTTL = 5000;
        //sixth get message size
        std::getline(iss, token, '\t');
        float textsize = std::stof(token);
        if(textsize==1){
          m.messageText = std::string(250, 't');
        }
        else{
          m.messageText = std::string(250, 'm');
        }
        ScheduleMessage scheduled_m;
        scheduled_m.m = m;
        scheduled_m.sendTime = sendtime;
        messagesToSend.push_back(scheduled_m);
        
    }
    //close the file
    inputFile.close();
    return messagesToSend;
} 

// --------------------------------------------------------------------------------------------------------------------------------------------
// MAIN
// --------------------------------------------------------------------------------------------------------------------------------------------
int main(int argc, char* argv[]) {

    //command line arguments
    nodeCount = std::atoi(argv[1]); //number of messages each node should send
    std::string traffic_model = argv[2]; //which traffic model
    std::string mobility_model = argv[3]; //which mobility model
    int groupSize = std::atoi(argv[4]); //group size
    std::string runiter = argv[5]; //run iteration

    //configure output files
    std::string outputpath = "../protest/results/routing/static_routing/"+traffic_model+"/"+mobility_model+"/node"+std::to_string(nodeCount)+"/group"+std::to_string(groupSize)+"/"+std::to_string(maxBufferSize)+"/";
    if(!std::filesystem::exists(outputpath)){
      std::cout << "Path doesn't exist. Creating it..." << std::endl;
      if(std::filesystem::create_directories(outputpath)){
        std::cout << "Directory created successfully" << std::endl;
      }
      else{
        std::cerr << "Failed to create directory." << std::endl;
      }
    }
    std::string messageSentTime_outputfile= "../protest/results/routing/static_routing/"+traffic_model+"/"+mobility_model+"/node"+std::to_string(nodeCount)+"/group"+std::to_string(groupSize)+"/"+std::to_string(maxBufferSize)+"/messageSentTime"+runiter+".csv";
    std::string messageSenderMap_outputfile = "../protest/results/routing/static_routing/"+traffic_model+"/"+mobility_model+"/node"+std::to_string(nodeCount)+"/group"+std::to_string(groupSize)+"/"+std::to_string(maxBufferSize)+"/messageSenderMap"+runiter+".csv";
    std::string messageReceivedTime_outputfile = "../protest/results/routing/static_routing/"+traffic_model+"/"+mobility_model+"/node"+std::to_string(nodeCount)+"/group"+std::to_string(groupSize)+"/"+std::to_string(maxBufferSize)+"/messageReceivedTime"+runiter+".csv";
    std::string messageReceiverMap_outputfile = "../protest/results/routing/static_routing/"+traffic_model+"/"+mobility_model+"/node"+std::to_string(nodeCount)+"/group"+std::to_string(groupSize)+"/"+std::to_string(maxBufferSize)+"/messageReceiverMap"+runiter+".csv";
    std::string metadata_outputfile = "../protest/results/routing/static_routing/"+traffic_model+"/"+mobility_model+"/node"+std::to_string(nodeCount)+"/group"+std::to_string(groupSize)+"/"+std::to_string(maxBufferSize)+"/metadata"+runiter+".csv";
    std::string fullness_outputfile = "../protest/results/routing/static_routing/"+traffic_model+"/"+mobility_model+"/node"+std::to_string(nodeCount)+"/group"+std::to_string(groupSize)+"/"+std::to_string(maxBufferSize)+"/bufferFullness"+runiter+".csv";
    packetFile = "../protest/results/routing/static_routing/"+traffic_model+"/"+mobility_model+"/node"+std::to_string(nodeCount)+"/group"+std::to_string(groupSize)+"/"+std::to_string(maxBufferSize)+"/packets"+runiter+".csv";

    std::ofstream buff_file;
    buff_file.open (fullness_outputfile);
    buff_file.close();

    std::ofstream pack_file;
    pack_file.open (packetFile);
    pack_file.close();
    
    //configure input files
    std::string mobilityfile = "../protest/mobility_models/trace_files/"+mobility_model+"/node"+std::to_string(nodeCount)+"/1.txt";
    std::string trafficfile = "../protest/traffic_models/"+traffic_model+"/"+mobility_model+"/node"+std::to_string(nodeCount)+"/group"+std::to_string(groupSize)+"/1.txt";
    std::string groupfile = "../protest/groups/"+traffic_model+"/"+mobility_model+"/node"+std::to_string(nodeCount)+"/group"+std::to_string(groupSize)+"/1.txt";

    //account for ARP configuration in simulation length
    simLen = simLen + (nodeCount * (nodeCount-1) * .01) + 10;

    NS_LOG_UNCOND("--------------------------------------------------------------------------------------------------------------------------------------------");

    //add nodes to node container
    nodes.Create(nodeCount); 

    //create array of node handlers 
    for (uint32_t i = 0; i < nodeCount; ++i) {
        nodeHandlerArray.push_back(NodeHandler());
    }

    //import mobility model
    Ns2MobilityHelper ns2 = Ns2MobilityHelper (mobilityfile);
    //install mobility model
    ns2.Install();

    NS_LOG_UNCOND("--------------------------------------------------------------------------------------------------------------------------------------------");

    // ----------------------------------------------------------------------------------------
    // Set up channels
    // ----------------------------------------------------------------------------------------
    
    std::vector<NetDeviceContainer> deviceContainers; 

    //create advertising channels
    //three channels [like irl; 3,6,11]
    for(int channelIter = 0; channelIter < 3; channelIter++){
        WifiHelper dataWifi;
        // 802.11ax (Wi-Fi 6)
        dataWifi.SetStandard(WIFI_STANDARD_80211ax);
        // Configure the physical layer
        YansWifiPhyHelper dataWifiPhy;
        // For advertising channels, we want 20 MHz on a 2.4GHz band
        dataWifiPhy.Set("ChannelSettings", StringValue("{0, 20, BAND_2_4GHZ, 0}"));
        // No gain added
        dataWifiPhy.Set("RxGain", DoubleValue(0));
        // Transmission power (reach of device signal - around that of a smartphone allegedly)
        dataWifiPhy.Set("TxPowerStart", DoubleValue (15.0));
        dataWifiPhy.Set("TxPowerEnd", DoubleValue (15.0));
        YansWifiChannelHelper dataChannel;
        YansWifiPhyHelper dataWifiPhyHelper;
        // Signal propagation only up to 10m 
        dataChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
        dataChannel.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
        dataChannel.AddPropagationLoss ("ns3::RangePropagationLossModel", "MaxRange", DoubleValue (10));
        dataWifiPhy.SetChannel(dataChannel.Create());
        // Add a mac and disable rate control
        WifiMacHelper dataWifiMac;
        // Set data rate - He MCS 11 [one spatial stream, 1024-QAM modulation, 5/6 coding, and a .8 guard interval]
        std::string phyMode("HeMcs11");
        // Fix non-unicast data rate to be the same as unicast
        Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(phyMode));
        dataWifi.SetRemoteStationManager("ns3::ConstantRateWifiManager","DataMode", StringValue(phyMode), "ControlMode", StringValue(phyMode));
        // Set Wi-Fi to adhoc mode
        dataWifiMac.SetType("ns3::AdhocWifiMac");
        NetDeviceContainer dataDevices = dataWifi.Install(dataWifiPhy, dataWifiMac, nodes);
        // Add Layer 2 Callback for Testing
        // for(int i=0; i<nodeCount; i++){
        //   Ptr<NetDevice> d = dataDevices.Get(i);
        //   ns3::Callback c = MakeCallback(&ReceivePromiscDevice);
        //   d->SetPromiscReceiveCallback(c);           
        // }
        deviceContainers.push_back(dataDevices);
    }

    //create data exchange channels
    //three channels [like irl???]
    for(int channelIter = 0; channelIter < 3; channelIter++){
        WifiHelper dataWifi;
        // 802.11ax (Wi-Fi 6)
        dataWifi.SetStandard(WIFI_STANDARD_80211ax);
        YansWifiPhyHelper dataWifiPhy;
        // For data exchange channels, we use 80 MHz on a 5GHz band
        dataWifiPhy.Set("ChannelSettings", StringValue("{0, 80, BAND_5GHZ, 0}"));
        // No gain added
        dataWifiPhy.Set("RxGain", DoubleValue(0));
        // Transmission power (reach of device signal - around that of a smartphone allegedly)
        dataWifiPhy.Set("TxPowerStart", DoubleValue (15.0));
        dataWifiPhy.Set("TxPowerEnd", DoubleValue (15.0));
        YansWifiChannelHelper dataChannel;
        YansWifiPhyHelper dataWifiPhyHelper;
        // Signal propagation only up to 10m 
        dataChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
        dataChannel.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
        dataChannel.AddPropagationLoss ("ns3::RangePropagationLossModel", "MaxRange", DoubleValue (10));
        dataWifiPhy.SetChannel(dataChannel.Create());
        // Add a mac and disable rate control
        WifiMacHelper dataWifiMac;
        // Set data rate - He MCS 6 [one spatial stream, 64-QAM modulation, 3/4 coding, and a .8 guard interval]
        std::string phyMode("HeMcs6");
        // Fix non-unicast data rate to be the same as that of unicast
        Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(phyMode));
        dataWifi.SetRemoteStationManager("ns3::ConstantRateWifiManager","DataMode", StringValue(phyMode), "ControlMode", StringValue(phyMode));
        // Set it to adhoc mode
        dataWifiMac.SetType("ns3::AdhocWifiMac");
        NetDeviceContainer dataDevices = dataWifi.Install(dataWifiPhy, dataWifiMac, nodes);
        // Add Layer 2 Callback for Testing
        // for(int i=0; i<nodeCount; i++){
        //   Ptr<NetDevice> d = dataDevices.Get(i);
        //   ns3::Callback c = MakeCallback(&ReceivePromiscDevice);
        //   d->SetPromiscReceiveCallback(c);          
        // }
        deviceContainers.push_back(dataDevices);
    }

    // ----------------------------------------------------------------------------------------
    // Install Internet stack on nodes
    // ----------------------------------------------------------------------------------------
    
    InternetStackHelper internet;
    internet.Install(nodes);

    // ----------------------------------------------------------------------------------------
    // Assign IP addresses to the devices
    // ----------------------------------------------------------------------------------------
    
    //set IP and mask
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.0.0.0", "255.0.0.0");

    //create interface container for interfaces for given devices
    std::vector<Ipv4InterfaceContainer> interfaceContainers; 
    for(int channelIter = 0; channelIter < 6; channelIter++){
      Ipv4InterfaceContainer dataInterface = ipv4.Assign(deviceContainers[channelIter]);
      interfaceContainers.push_back(dataInterface);
    }
    
    //create static node cliques
    createCliques(groupfile);

    // ----------------------------------------------------------------------------------------
    // Initialize map between node #s and their IP addresses
    // ----------------------------------------------------------------------------------------

    for(int channelIter = 0; channelIter < 6; channelIter++){
      MapIPAddresses(interfaceContainers[channelIter],channelIter, nodeCount);
    }

    // ----------------------------------------------------------------------------------------
    // Print current seconds for status tracking
    // ----------------------------------------------------------------------------------------
    
    for(int a = 0; a < simLen; a=a+100){
        Simulator::Schedule(Seconds(a), &LogTime, std::to_string(a)); 
    }

    // ----------------------------------------------------------------------------------------
    // Create sockets for each node on each channel
    // ----------------------------------------------------------------------------------------
    
    for(int channelIter = 0; channelIter < 3; channelIter++){
      std::vector<Ptr<Socket>> sockets;
      for (uint32_t i = 0; i < nodeCount; ++i) {
          Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(i), TypeId::LookupByName("ns3::UdpSocketFactory"));
          InetSocketAddress socketAddress = InetSocketAddress(Ipv4Address::GetAny(), 80);
          socket->Bind(socketAddress);
          socket->BindToNetDevice(deviceContainers[channelIter].Get(i));
          socket->SetRecvCallback(MakeCallback(&ReceivePacket)); 
          socket->SetAllowBroadcast(true); 
          sockets.push_back(socket);
      }
      advertiseSockets.push_back(sockets);
    }

    for(int channelIter = 3; channelIter < 6; channelIter++){
      std::vector<Ptr<Socket>> sockets;
      for (uint32_t i = 0; i < nodeCount; ++i) {
          Ptr<Socket> socket = Socket::CreateSocket(nodes.Get(i), TypeId::LookupByName("ns3::UdpSocketFactory"));
          InetSocketAddress socketAddress = InetSocketAddress(Ipv4Address::GetAny(), 80);
          socket->Bind(socketAddress);
          socket->BindToNetDevice(deviceContainers[channelIter].Get(i));
          socket->SetRecvCallback(MakeCallback(&ReceivePacket)); 
          socket->SetAllowBroadcast(true); 
          sockets.push_back(socket);
      }
      dataSockets.push_back(sockets);
    }

    // ----------------------------------------------------------------------------------------
    // Run the ARP process
    // ----------------------------------------------------------------------------------------
    
    for(int sender = 0; sender < nodeCount; sender++){
      for (int recvr = 0; recvr < nodeCount; recvr++) {
        if(sender!=recvr){
          for(int c = 0; c < 3; c++){
          //advertise sockets
            Simulator::Schedule(Seconds(arpSendTime), &SendARPMessage, advertiseSockets[c][sender], NodeToIp[c][recvr]);
          }
          for(int c = 0; c < 3; c++){
          //data sockets
            Simulator::Schedule(Seconds(arpSendTime), &SendARPMessage, dataSockets[c][sender], NodeToIp[c+3][recvr]);
          }
          arpSendTime = arpSendTime + .01; 
        }
      }
    }

    // ----------------------------------------------------------------------------------------
    // Prepare for actual testing
    // ----------------------------------------------------------------------------------------
    
    arpSendTime = arpSendTime + 10; 
    NS_LOG_UNCOND("ARPSEND: " << arpSendTime);
    Simulator::Schedule(Seconds(arpSendTime), &LogMessage, "--------------------------");

    // ----------------------------------------------------------------------------------------
    // Add message to buffer
    // ----------------------------------------------------------------------------------------
    
    std::vector<ScheduleMessage> schedule = GetTrafficModel(trafficfile);
    for (ScheduleMessage msg : schedule) {
        Message m;
        m.messageID = msg.m.messageID;
        m.sender = msg.m.sender;
        m.recipients = msg.m.recipients;
        m.messageTTL = msg.m.messageTTL;
        m.messageText = msg.m.messageText;
        if(m.recipients.size() > 1){
            Simulator::Schedule(Seconds(arpSendTime+msg.sendTime), &AddMessageToBuffer, m.sender, m);
        }
        else{
            Simulator::Schedule(Seconds(arpSendTime+msg.sendTime), &AddMessageToBuffer, m.sender, m);
        }
        messageSenderMap[m.messageID] = m.sender;
        messageReceiverMap[m.messageID] = m.recipients;
    }

    // ----------------------------------------------------------------------------------------
    // Send beacons
    // ----------------------------------------------------------------------------------------
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> offset_dist(0.0f, 60.0f);
    std::uniform_int_distribution<> channel_dist(0, 2);
    std::uniform_int_distribution<> recipient_dist(0, nodeCount-1);
    float timeIters = (lround(simLen - arpSendTime))/60;
    for(int t=0; t<timeIters; t++){
      for(int n=0; n<nodeCount; n++){
        float offset = offset_dist(gen);
        float c = channel_dist(gen);
        Simulator::Schedule(Seconds((t*60)+arpSendTime+offset), &SendAdvertisement_BeaconFrame, advertiseSockets[c][n], c, n);
      }
    }
    
    NS_LOG_UNCOND("--------------------------------------------------------------------------------------------------------------------------------------------");
    
    // ----------------------------------------------------------------------------------------
    // Run the simulation
    // ----------------------------------------------------------------------------------------
    
    Simulator::Stop(Seconds(simLen));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_UNCOND("--------------------------------------------------------------------------------------------------------------------------------------------");

    // ----------------------------------------------------------------------------------------
    // Evaluate Sim Performance
    // ----------------------------------------------------------------------------------------
    
    //messageSentTime
    std::ofstream sentTime_file;
    sentTime_file.open (messageSentTime_outputfile);
    for(std::map<string, float>::const_iterator it = messageSentTime.begin(); it != messageSentTime.end(); ++it)
    {
      sentTime_file << it->first << "," << it->second << "\n";
    }
    sentTime_file.close();

    //messageSenderMap
    std::ofstream sentMap_file;
    sentMap_file.open (messageSenderMap_outputfile);
    for(std::map<uint32_t, uint32_t>::const_iterator it = messageSenderMap.begin(); it != messageSenderMap.end(); ++it)
    {
      sentMap_file << it->first << "," << it->second << "\n";
    }
    sentMap_file.close();

    //messageReceivedTime
    std::ofstream recvTime_file;
    recvTime_file.open (messageReceivedTime_outputfile);
    for(std::map<string, float>::const_iterator it = messageReceivedTime.begin(); it != messageReceivedTime.end(); ++it)
    {
      recvTime_file << it->first << "," << it->second << "\n";
    }
    recvTime_file.close();

    //messageReceiverMap
    std::ofstream recvMap_file;
    recvMap_file.open (messageReceiverMap_outputfile);
    for(std::map<uint32_t, std::vector<uint32_t>>::const_iterator it = messageReceiverMap.begin(); it != messageReceiverMap.end(); ++it)
    {
      recvMap_file << it->first << ",[";
      for(const uint32_t& recvr : it->second){
        recvMap_file << recvr << "  ";
      }
      recvMap_file << "]\n";
    }
    recvMap_file.close();

    //metadata 
    std::ofstream metadata_file;
    metadata_file.open (metadata_outputfile);
    metadata_file << "Sim Length" << "," << simLen << "\n";
    metadata_file << "Arp Sent" << "," << arpsent << "\n";
    metadata_file << "Arp Recv" << "," << arprecv << "\n";
    metadata_file << "Send Messages" << "," << send_msgs << "\n";
    metadata_file << "Recv Messages" << "," << recv_msgs << "\n";
    metadata_file << "Send Digests" << "," << send_digs << "\n";
    metadata_file << "Recv Digests" << "," << recv_digs << "\n";
    metadata_file << "Send Beacons" << "," << send_beacons << "\n";
    metadata_file << "Recv Beacons" << "," << recv_beacons << "\n";
    metadata_file << "Send Probe Request" << "," << send_proberequest << "\n";
    metadata_file << "Recv Probe Request" << "," << recv_proberequest << "\n";
    metadata_file << "Send Probe Response" << "," << send_proberesponse << "\n";
    metadata_file << "Recv Probe Response" << "," << recv_proberesponse << "\n";
    metadata_file << "Age Message Drops" << "," << ageMessageDrops << "\n";
    metadata_file << "Space Message Drops" << "," << spaceMessageDrops << "\n";
    metadata_file.close();

    return 0;

}